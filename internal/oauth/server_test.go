package oauth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cuhawk/BastionAuth/internal/dpop"
	"github.com/cuhawk/BastionAuth/internal/exchange"
	"github.com/cuhawk/BastionAuth/internal/oauth"
	"github.com/cuhawk/BastionAuth/internal/store"
	"github.com/cuhawk/BastionAuth/internal/testutil"
)

const origin = "https://auth.example.test"
const redirect = "https://client.example.test/callback"
const verifier = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk"

func post(handler http.Handler, path string, p url.Values, proof string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", origin+path, strings.NewReader(p.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func TestConcurrentRevokeAndExchange(t *testing.T) {
	mem := store.NewMemory()
	keys := testutil.NewKeys()
	signer := keys.Signer("dpop+jwt", true)
	srv := oauth.Server{Tenant: "tenant", Origin: origin, Audience: "api", Clients: map[string]oauth.Client{"public": {}}, Store: mem, DPoP: dpop.Verifier{Store: mem}, Exchange: exchange.Service{Issuer: exchange.Issuer{Name: origin, Signer: keys.Signer("at+jwt", false)}}}
	handler := srv.Handler()
	ctx := context.Background()
	var postRevokeTokens atomic.Int32
	var wg sync.WaitGroup
	for worker := range 50 {
		wg.Go(func() {
			user := fmt.Sprintf("worker-%d", worker)
			for range 100 {
				add := func() string {
					code := store.Secret()
					c := store.Credential{User: user, Client: "public", Kind: "authorization_code", Redirect: redirect, Challenge: store.Digest(verifier), Scope: "read", Expires: time.Now().Add(time.Minute)}
					if err := mem.Consent(ctx, "tenant", store.Digest(code), c); err != nil {
						t.Error(err)
					}
					return code
				}
				token := func(grant, key, value string) *httptest.ResponseRecorder {
					p := url.Values{"grant_type": {grant}, "client_id": {"public"}, key: {value}}
					if grant == "authorization_code" {
						p.Set("redirect_uri", redirect)
						p.Set("code_verifier", verifier)
					}
					proof := testutil.Proof(signer, "POST", origin+"/oauth/token", "", store.Secret(), time.Now())
					return post(handler, "/oauth/token", p, proof)
				}
				initial := token("authorization_code", "code", add())
				var initialResponse struct {
					Refresh string `json:"refresh_token"`
				}
				if err := json.Unmarshal(initial.Body.Bytes(), &initialResponse); err != nil || initial.Code != 200 || initialResponse.Refresh == "" {
					t.Errorf("setup refresh: %d %s", initial.Code, initial.Body)
					return
				}
				raceCode, pending := add(), add()
				outcome := make(chan *httptest.ResponseRecorder, 1)
				go func() { outcome <- token("authorization_code", "code", raceCode) }()
				if err := srv.RevokeGrant(ctx, user, "public"); err != nil {
					t.Error(err)
					return
				}
				if w := token("authorization_code", "code", pending); w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_grant") {
					if w.Code == 200 {
						postRevokeTokens.Add(1)
					}
					t.Errorf("pending code after revoke: %d %s", w.Code, w.Body)
				}
				if w := token("refresh_token", "refresh_token", initialResponse.Refresh); w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_grant") {
					if w.Code == 200 {
						postRevokeTokens.Add(1)
					}
					t.Errorf("pre-existing refresh after revoke: %d %s", w.Code, w.Body)
				}
				w := <-outcome
				switch w.Code {
				case 200:
					var response struct {
						Refresh string `json:"refresh_token"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.Refresh == "" {
						t.Errorf("invalid token response: %s", w.Body)
						continue
					}
					if w := token("refresh_token", "refresh_token", response.Refresh); w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_grant") {
						if w.Code == 200 {
							postRevokeTokens.Add(1)
						}
						t.Errorf("refresh after revoke: %d %s", w.Code, w.Body)
					}
				case 400:
					if !strings.Contains(w.Body.String(), "invalid_grant") {
						t.Errorf("unexpected result: %s", w.Body)
					}
				default:
					t.Errorf("exchange result: %d %s", w.Code, w.Body)
				}
				fresh := add()
				if w := token("authorization_code", "code", fresh); w.Code != 200 {
					t.Errorf("re-consent: %d %s", w.Code, w.Body)
				}
				if w := token("authorization_code", "code", fresh); w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_grant") {
					t.Errorf("code reused: %d %s", w.Code, w.Body)
				}
			}
		})
	}
	wg.Wait()
	if n := postRevokeTokens.Load(); n != 0 {
		t.Fatalf("%d post-revoke tokens issued", n)
	}
	t.Log("0 post-revoke tokens issued across 5000 revoke/exchange races")
}

func TestAuthorizePKCEAndState(t *testing.T) {
	keys := testutil.NewKeys()
	jwks := keys.JWKS()
	defer jwks.Close()
	srv := oauth.Server{Tenant: "tenant", Origin: origin, Clients: map[string]oauth.Client{"public": {Redirects: []string{redirect}, Scopes: []string{"read"}}}, Store: store.NewMemory(), Sessions: exchange.Verifier{Keys: &exchange.JWKS{URL: jwks.URL}, Issuer: "identity", Audience: "session"}}
	handler := srv.Handler()
	form := url.Values{"client_id": {"public"}, "redirect_uri": {redirect}, "scope": {"read"}, "state": {"client-generated-csrf"}, "code_challenge": {store.Digest(verifier)}, "code_challenge_method": {"plain"}, "response_type": {"code"}, "decision": {"approve"}}
	if w := post(handler, "/oauth/authorize", form, ""); w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_request") {
		t.Fatalf("plain PKCE: %d %s", w.Code, w.Body)
	}
	form.Set("code_challenge_method", "S256")
	session := testutil.Access(keys.Signer("at+jwt", false), "identity", "tenant", "user", "session", "session", nil, nil)
	request := httptest.NewRequest("GET", origin+"/oauth/authorize?"+form.Encode(), nil)
	request.AddCookie(&http.Cookie{Name: "__Host-bastion_session", Value: session})
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, request)
	binding := regexp.MustCompile(`name="consent_binding" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
	if page.Code != 200 || len(binding) != 2 {
		t.Fatalf("consent form: %d %s", page.Code, page.Body)
	}
	form.Set("consent_binding", binding[1])
	send := func(dp string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", origin+"/oauth/authorize", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", dp)
		req.AddCookie(&http.Cookie{Name: "__Host-bastion_session", Value: session})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	if w := send("https://foreign.test"); w.Code != 400 {
		t.Fatalf("cross-origin consent: %d", w.Code)
	}
	form.Set("state", "tampered")
	if w := send(origin); w.Code != 400 {
		t.Fatalf("tampered state: %d", w.Code)
	}
	form.Set("state", "client-generated-csrf")
	w := send(origin)
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil || w.Code != 303 || u.Query().Get("state") != form.Get("state") || u.Query().Get("code") == "" {
		t.Fatalf("consent redirect: %d %s", w.Code, w.Header().Get("Location"))
	}
	form.Set("redirect_uri", redirect+"/")
	if w := send(origin); w.Code != 400 || w.Header().Get("Location") != "" {
		t.Fatalf("redirect mismatch: %d", w.Code)
	}
}
