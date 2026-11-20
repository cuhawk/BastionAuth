package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cuhawk/BastionAuth/internal/dpop"
	"github.com/cuhawk/BastionAuth/internal/exchange"
	"github.com/cuhawk/BastionAuth/internal/store"
	"github.com/cuhawk/BastionAuth/internal/testutil"
)

func TestMetadataEgress(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.100.100.200", "168.63.129.16", "::1", "::ffff:127.0.0.1", "fd00:ec2::254", "fe80::1", "ff02::1", "64:ff9b::a00:1", "2002:a00:1::1"} {
		t.Run(ip, func(t *testing.T) {
			if publicMetadataIP(netip.MustParseAddr(ip)) {
				t.Fatal("non-public address allowed")
			}
		})
	}
	for _, ip := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if !publicMetadataIP(netip.MustParseAddr(ip)) {
			t.Errorf("global address rejected: %s", ip)
		}
	}
	var hits atomic.Int32
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer endpoint.Close()
	resolver := NewCIMDResolver()
	if _, err := resolver.resolve(t.Context(), endpoint.URL+"/client.json"); err == nil || hits.Load() != 0 {
		t.Fatalf("local request: %v, hits %d", err, hits.Load())
	}
}

type metadataRoundTripper func(*http.Request) (*http.Response, error)

func (f metadataRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMetadataValidation(t *testing.T) {
	const id = "https://client.example/client.json"
	const valid = `{"client_id":"https://client.example/client.json","redirect_uris":["https://client.example/callback","http://127.0.0.1:6789/callback"],"token_endpoint_auth_method":"none"}`
	for _, tc := range []struct {
		name, body string
		status     int
		valid      bool
	}{
		{"valid", valid, 200, true},
		{"64 KiB", valid + strings.Repeat(" ", maxMetadataBytes-len(valid)), 200, true},
		{"over 64 KiB", valid + strings.Repeat(" ", maxMetadataBytes-len(valid)+1), 200, false},
		{"duplicate identity", strings.Replace(valid, `"client_id":`, `"client_id":"https://unrelated.example/x","client_id":`, 1), 200, false},
		{"wrong identity", strings.Replace(valid, "client.json", "other.json", 1), 200, false},
		{"wrong method", strings.Replace(valid, "\"none\"", "\"client_secret_basic\"", 1), 200, false},
		{"empty redirects", `{"client_id":"https://client.example/client.json","redirect_uris":[]}`, 200, false},
		{"invalid redirect", strings.Replace(valid, "https://client.example/callback", "javascript://client.example/callback", 1), 200, false},
		{"credentials in redirect", strings.Replace(valid, "https://client.example/callback", "https://user@client.example/callback", 1), 200, false},
		{"reserved redirect query", strings.Replace(valid, "https://client.example/callback", "https://client.example/callback?code=preloaded", 1), 200, false},
		{"fragment in redirect", strings.Replace(valid, "https://client.example/callback", "https://client.example/callback#", 1), 200, false},
		{"redirect response", "", 302, false},
		{"unsolicited not modified", "", 304, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := NewCIMDResolver()
			resolver.client.Transport = metadataRoundTripper(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != id {
					t.Fatalf("unexpected fetch %s", r.URL)
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: http.Header{"Location": {"https://other.example/"}}}, nil
			})
			doc, err := resolver.resolve(t.Context(), id)
			if (err == nil) != tc.valid || (tc.valid && doc.ID != id) {
				t.Fatalf("metadata validity: %+v %v", doc, err)
			}
		})
	}
	for _, invalid := range []string{"http://client.example/client.json", "https://client.example", "https://client.example/client.json#", "https://client.example/client.json?x=y", "https://user@client.example/client.json"} {
		if metadataURL(invalid) {
			t.Errorf("invalid client ID accepted: %s", invalid)
		}
	}
}

func TestMetadataConditionalCache(t *testing.T) {
	const id = "https://client.example/client.json"
	var requests atomic.Int32
	resolver := NewCIMDResolver()
	resolver.client.Transport = metadataRoundTripper(func(r *http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set("ETag", `"first"`)
		switch requests.Add(1) {
		case 1:
			header.Set("Cache-Control", "max-age=0")
			document, err := json.Marshal(metadataDocument{ID: id, Redirects: []string{"https://client.example/callback"}})
			if err != nil {
				return nil, err
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(document))), Header: header}, nil
		case 2:
			if r.Header.Get("If-None-Match") != `"first"` {
				return nil, fmt.Errorf("missing ETag validation")
			}
			header.Set("Cache-Control", "max-age=60")
			return &http.Response{StatusCode: 304, Body: http.NoBody, Header: header}, nil
		default:
			return nil, fmt.Errorf("unexpected request")
		}
	})
	for range 2 {
		if doc, err := resolver.resolve(t.Context(), id); err != nil || doc.ID != id {
			t.Fatalf("lookup: %+v %v", doc, err)
		}
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, err := resolver.resolve(t.Context(), id); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if requests.Load() != 2 {
		t.Fatalf("%d network requests", requests.Load())
	}
}

func TestMetadataClientOAuthEndpoints(t *testing.T) {
	const id = "https://client.example/client.json"
	const callback = "https://client.example/callback"
	const origin = "https://auth.example"
	const pkce = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk"
	resolver := NewCIMDResolver()
	var fetches atomic.Int32
	resolver.client.Transport = metadataRoundTripper(func(r *http.Request) (*http.Response, error) {
		fetches.Add(1)
		if r.URL.String() != id {
			return nil, fmt.Errorf("unexpected URL: %s", r.URL)
		}
		document := `{"client_id":"https://client.example/client.json","client_name":"MCP <client>","redirect_uris":["https://client.example/callback"]}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(document)), Header: make(http.Header)}, nil
	})
	db := store.NewMemory()
	keys := testutil.NewKeys()
	jwks := keys.JWKS()
	defer jwks.Close()
	signer := keys.Signer("at+jwt", false)
	proofSigner := keys.Signer("dpop+jwt", true)
	s := Server{Tenant: "tenant", Origin: origin, Audience: "api", Store: db, CIMD: resolver, CIMDScopes: []string{"read"},
		Sessions: exchange.Verifier{Keys: &exchange.JWKS{URL: jwks.URL}, Issuer: "identity", Audience: "session"},
		DPoP:     dpop.Verifier{Store: db}, Exchange: exchange.Service{Issuer: exchange.Issuer{Name: origin, Signer: signer}}}
	handler := s.Handler()
	discovery := httptest.NewRecorder()
	handler.ServeHTTP(discovery, httptest.NewRequest(http.MethodGet, origin+"/.well-known/oauth-authorization-server", nil))
	var metadata map[string]any
	if err := json.Unmarshal(discovery.Body.Bytes(), &metadata); discovery.Code != 200 || err != nil ||
		metadata["client_id_metadata_document_supported"] != true || metadata["pushed_authorization_request_endpoint"] != origin+"/oauth/par" {
		t.Fatalf("authorization server discovery: %d %s (%v)", discovery.Code, discovery.Body, err)
	}
	session := testutil.Access(signer, "identity", "tenant", "user", "session", "session", nil, nil)
	params := url.Values{"client_id": {id}, "redirect_uri": {callback}, "scope": {"read"}, "response_type": {"code"}, "state": {"state"}, "code_challenge_method": {"S256"}, "code_challenge": {store.Digest(pkce)}}
	authorize := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, origin+"/oauth/authorize?"+params.Encode(), nil)
		req.AddCookie(&http.Cookie{Name: "__Host-bastion_session", Value: session})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	params.Set("redirect_uri", callback+"?extra=true")
	if w := authorize(); w.Code != 400 || w.Header().Get("Location") != "" {
		t.Fatalf("unlisted redirect accepted: %d %s", w.Code, w.Body)
	}
	params.Set("redirect_uri", callback)
	params.Set("scope", "admin")
	if w := authorize(); w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_scope") {
		t.Fatalf("unapproved scope: %d %s", w.Code, w.Body)
	}
	params.Set("scope", "read")
	if w := authorize(); w.Code != 200 || !strings.Contains(w.Body.String(), "MCP &lt;client&gt;") {
		t.Fatalf("CIMD consent: %d %s", w.Code, w.Body)
	}
	params.Set("consent_binding", consentBinding(session, params))
	params.Set("decision", "approve")
	req := httptest.NewRequest(http.MethodPost, origin+"/oauth/authorize", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	req.AddCookie(&http.Cookie{Name: "__Host-bastion_session", Value: session})
	approved := httptest.NewRecorder()
	handler.ServeHTTP(approved, req)
	location, err := url.Parse(approved.Header().Get("Location"))
	if err != nil || approved.Code != 303 || location.Query().Get("code") == "" {
		t.Fatalf("CIMD approval: %d %s", approved.Code, approved.Body)
	}
	form := url.Values{"client_id": {id}, "redirect_uri": {callback}, "grant_type": {"authorization_code"},
		"code": {location.Query().Get("code")}, "code_verifier": {pkce}}
	token := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, origin+"/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("DPoP", testutil.Proof(proofSigner, http.MethodPost, origin+"/oauth/token", "", store.Secret(), time.Now()))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	form.Set("client_secret", "unexpected")
	if w := token(); w.Code != 401 {
		t.Fatalf("metadata client authenticated with secret: %d %s", w.Code, w.Body)
	}
	form.Del("client_secret")
	if w := token(); w.Code != 200 {
		t.Fatalf("metadata token request: %d %s", w.Code, w.Body)
	}
	if fetches.Load() != 1 {
		t.Fatalf("expected one metadata fetch, got %d", fetches.Load())
	}
}
