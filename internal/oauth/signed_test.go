package oauth

import (
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
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
	"github.com/cuhawk/BastionAuth/internal/joseutil"
	"github.com/cuhawk/BastionAuth/internal/store"
	"github.com/cuhawk/BastionAuth/internal/testutil"
	"github.com/go-jose/go-jose/v4"
)

const testIssuer = "https://issuer.example"
const testOrigin = "https://auth.example"
const testRedirect = "https://client.example/callback"
const testURI = "https://client.example/request.jwt"

func jwtSigner(t *testing.T, alg jose.SignatureAlgorithm, key any, kid, typ string) jose.Signer {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func jwtFixture() map[string]any {
	now := time.Now()
	return map[string]any{"iss": "signed", "aud": testIssuer, "jti": store.Secret(), "exp": now.Add(time.Minute).Unix(), "nbf": now.Add(-time.Second).Unix()}
}

func TestSignedJWTValidation(t *testing.T) {
	keys := testutil.NewKeys()
	key := jose.JSONWebKey{Key: keys.Public, KeyID: "registered", Use: "sig"}
	signer := jwtSigner(t, jose.EdDSA, keys.Private, key.KeyID, "oauth-authz-req+jwt")
	for _, tc := range []struct {
		name, claim string
		value       any
	}{
		{"issuer", "iss", "other"}, {"audience", "aud", "https://other.example"},
		{"multiple audiences", "aud", []string{testIssuer, "https://other.example"}},
		{"expired", "exp", time.Now().Add(-time.Minute).Unix()},
		{"excessive expiry", "exp", time.Now().Add(time.Hour).Unix()},
		{"future nbf", "nbf", time.Now().Add(time.Second * 30).Unix()},
		{"missing nbf", "nbf", nil}, {"overflow nbf", "nbf", 1e100}, {"missing exp", "exp", nil},
		{"empty jti", "jti", ""}, {"wrong type", "jti", 42},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := jwtFixture()
			fixture[tc.claim] = tc.value
			claims, err := signedClaims(testutil.Signed(signer, fixture), []jose.JSONWebKey{key}, false)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := validateSignedClaims(claims, "signed", []string{testIssuer}, time.Now(), false); err == nil {
				t.Fatal("invalid claims accepted")
			}
		})
	}
	hmacSigner := jwtSigner(t, jose.HS256, []byte(keys.Public), key.KeyID, "JWT")
	encode := base64.RawURLEncoding.EncodeToString
	for _, raw := range []string{
		encode([]byte(`{"alg":"none"}`)) + "." + encode([]byte("{}")) + ".",
		testutil.Signed(hmacSigner, jwtFixture()),
		testutil.Signed(jwtSigner(t, jose.EdDSA, testutil.NewKeys().Private, key.KeyID, "JWT"), jwtFixture()),
	} {
		if _, err := signedClaims(raw, []jose.JSONWebKey{key}, false); err == nil {
			t.Fatal("invalid signature accepted")
		}
	}
	if _, err := signedClaims(testutil.Signed(signer, jwtFixture()), []jose.JSONWebKey{key}, true); err == nil {
		t.Fatal("request object accepted as assertion")
	}
}

type requestTransport func(*http.Request) (*http.Response, error)

func (f requestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSignedOAuthFlowsAndMetrics(t *testing.T) {
	mem := store.NewMemory()
	keys := testutil.NewKeys()
	key := jose.JSONWebKey{Key: keys.Public, KeyID: "registered", Use: "sig"}
	thumb, err := joseutil.Thumbprint(key)
	if err != nil {
		t.Fatal(err)
	}
	jarSigner := jwtSigner(t, jose.EdDSA, keys.Private, key.KeyID, "oauth-authz-req+jwt")
	assertionSigner := jwtSigner(t, jose.EdDSA, keys.Private, thumb, "JWT")
	issuerSigner := keys.Signer("at+jwt", false)
	jwks := keys.JWKS()
	defer jwks.Close()
	proofSigner := testutil.NewKeys().Signer("dpop+jwt", true)
	s := Server{
		Tenant: "tenant", Origin: testOrigin, Audience: "api", Store: mem,
		Clients: map[string]Client{"signed": {
			Redirects: []string{testRedirect}, Scopes: []string{"read"}, JWTKeys: []jose.JSONWebKey{key},
			RequireJAR: true, PrivateKeyJWT: true, RequestURIs: []string{testURI},
		}},
		Exchange: exchange.Service{Issuer: exchange.Issuer{Name: testIssuer, Signer: issuerSigner}},
		Sessions: exchange.Verifier{Keys: &exchange.JWKS{URL: jwks.URL}, Issuer: "identity", Audience: "session"},
		DPoP:     dpop.Verifier{Store: mem},
	}
	if err := s.Clients["signed"].ValidateSigning(); err != nil {
		t.Fatal(err)
	}
	const verifier = "01234567890123456789012345678901234567890123456789"
	jarClaims := func() map[string]any {
		claims := jwtFixture()
		claims["client_id"] = "signed"
		claims["redirect_uri"] = testRedirect
		claims["response_type"] = "code"
		claims["state"] = "original"
		claims["scope"] = "read"
		claims["code_challenge_method"] = "S256"
		claims["code_challenge"] = store.Digest(verifier)
		claims["authorization_details"] = []map[string]string{{"type": "inventory"}}
		return claims
	}
	referenced := testutil.Signed(jarSigner, jarClaims())
	var fetches atomic.Int32
	s.requestObjects = &http.Client{Transport: requestTransport(func(r *http.Request) (*http.Response, error) {
		fetches.Add(1)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(referenced))}, nil
	})}
	handler := s.Handler()
	session := testutil.Access(issuerSigner, "identity", "tenant", "user", "session", "session", nil, nil)
	send := func(method, path string, form url.Values, proof string, login bool) *httptest.ResponseRecorder {
		var body io.Reader
		if method == http.MethodGet && len(form) != 0 {
			path += "?" + form.Encode()
		} else if method == http.MethodPost {
			body = strings.NewReader(form.Encode())
		}
		r := httptest.NewRequest(method, testOrigin+path, body)
		if body != nil {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", testOrigin)
		}
		if proof != "" {
			r.Header.Set("DPoP", proof)
		}
		if login {
			r.AddCookie(&http.Cookie{Name: "__Host-bastion_session", Value: session})
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	expect := func(w *httptest.ResponseRecorder, status int, body string) {
		t.Helper()
		if w.Code != status || !strings.Contains(w.Body.String(), body) {
			t.Fatalf("wanted %d %q, got %d %s", status, body, w.Code, w.Body)
		}
	}
	authz := func(form url.Values) *httptest.ResponseRecorder {
		return send(http.MethodGet, "/oauth/authorize", form, "", true)
	}
	inline := url.Values{"client_id": {"signed"}, "request": {testutil.Signed(jarSigner, jarClaims())}}
	expect(send(http.MethodGet, "/oauth/authorize", inline, "", false), 401, "login_required")
	inline.Set("state", "override")
	expect(authz(inline), 400, "invalid_request")
	inline.Del("state")
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			w := authz(inline)
			if w.Code == 200 {
				wins.Add(1)
			} else if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_request_object") {
				t.Errorf("unexpected concurrent JAR response: %d %s", w.Code, w.Body)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("JAR replay winners: %d", wins.Load())
	}
	ref := url.Values{"client_id": {"signed"}, "request_uri": {"https://unregistered.example/file"}}
	expect(authz(ref), 400, "invalid_request_uri")
	ref.Set("request_uri", testURI)
	expect(authz(ref), 200, "original")
	if fetches.Load() != 1 {
		t.Fatalf("request URI fetches: %d", fetches.Load())
	}
	assertion := func(aud string, signer jose.Signer) string {
		claims := jwtFixture()
		claims["sub"] = "signed"
		claims["aud"] = aud
		return testutil.Signed(signer, claims)
	}
	par := url.Values{"request": {testutil.Signed(jarSigner, jarClaims())}, "client_assertion_type": {assertionType}}
	expect(send(http.MethodPost, "/oauth/par", par, "", false), 401, "invalid_client")
	par.Set("client_assertion", assertion(testOrigin+"/oauth/token", assertionSigner))
	expect(send(http.MethodPost, "/oauth/par", par, "", false), 401, "invalid_client")
	par.Set("client_assertion", assertion(testIssuer, jwtSigner(t, jose.EdDSA, keys.Private, key.KeyID, "JWT")))
	expect(send(http.MethodPost, "/oauth/par", par, "", false), 401, "invalid_client")
	par.Set("client_assertion", assertion(testIssuer, assertionSigner))
	pushed := send(http.MethodPost, "/oauth/par", par, "", false)
	expect(pushed, 201, "request_uri")
	var response struct {
		URI string `json:"request_uri"`
	}
	if err := json.Unmarshal(pushed.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	page := authz(url.Values{"client_id": {"signed"}, "request_uri": {response.URI}})
	expect(page, 200, "original")
	expect(authz(url.Values{"client_id": {"signed"}, "request_uri": {response.URI}}), 400, "invalid_request_uri")
	expect(send(http.MethodPost, "/oauth/par", par, "", false), 401, "invalid_client")
	par.Set("client_assertion", assertion(testIssuer, assertionSigner))
	expect(send(http.MethodPost, "/oauth/par", par, "", false), 400, "invalid_request_object")

	consent := url.Values{"decision": {"approve"}}
	inputs := regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)"`)
	for _, match := range inputs.FindAllStringSubmatch(page.Body.String(), -1) {
		consent.Set(match[1], html.UnescapeString(match[2]))
	}
	nonce := consent.Get("signed_consent")
	consent.Del("signed_consent")
	expect(send(http.MethodPost, "/oauth/authorize", consent, "", true), 400, "invalid_request")
	consent.Set("signed_consent", nonce)
	approved := send(http.MethodPost, "/oauth/authorize", consent, "", true)
	expect(approved, 303, "")
	expect(send(http.MethodPost, "/oauth/authorize", consent, "", true), 400, "invalid_request")
	location, err := url.Parse(approved.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" || location.Query().Get("state") != "original" {
		t.Fatalf("invalid authorization redirect: %v (%v)", location, err)
	}
	code := location.Query().Get("code")
	token := url.Values{"grant_type": {"authorization_code"}, "client_id": {"signed"}, "code": {code}, "redirect_uri": {testRedirect}, "code_verifier": {verifier}}
	proof := testutil.Proof(proofSigner, "POST", testOrigin+"/oauth/token", "", store.Secret(), time.Now())
	expect(send(http.MethodPost, "/oauth/token", token, proof, false), 401, "invalid_client")
	token.Set("client_assertion_type", assertionType)
	token.Set("client_assertion", assertion(testOrigin+"/oauth/token", assertionSigner))
	expect(send(http.MethodPost, "/oauth/token", token, proof, false), 200, "access_token")
	expect(send(http.MethodPost, "/oauth/token", token, proof, false), 401, "invalid_client")
	token.Set("grant_type", exchange.GrantType)
	expect(send(http.MethodPost, "/oauth/token", token, "", false), 401, "invalid_client")

	scrape := send(http.MethodGet, "/metrics", nil, "", false)
	for _, sample := range []string{
		"# TYPE http_request_duration_seconds histogram",
		"oauth_par_requests_total{outcome=\"success\"} 1",
		"oauth_par_requests_total{outcome=\"client_error\"} 5",
		"oauth_exchange_requests_total{outcome=\"client_error\"} 1",
		"# TYPE oauth_requests_total counter",
	} {
		expect(scrape, 200, sample)
	}
	if scrape.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("existing security middleware did not wrap metrics")
	}
}
