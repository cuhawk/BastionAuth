package oauth_test

import (
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cuhawk/BastionAuth/internal/dpop"
	"github.com/cuhawk/BastionAuth/internal/exchange"
	"github.com/cuhawk/BastionAuth/internal/joseutil"
	"github.com/cuhawk/BastionAuth/internal/oauth"
	"github.com/cuhawk/BastionAuth/internal/store"
	"github.com/cuhawk/BastionAuth/internal/testutil"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestPARConsentAndTokenDetails(t *testing.T) {
	keys := testutil.NewKeys()
	jwks := keys.JWKS()
	defer jwks.Close()
	mem := store.NewMemory()
	signer := keys.Signer("at+jwt", false)
	proofSigner := keys.Signer("dpop+jwt", true)
	srv := oauth.Server{Tenant: "tenant", Origin: origin, Audience: "api", Store: mem,
		Clients:  map[string]oauth.Client{"public": {Redirects: []string{redirect}, Scopes: []string{"read"}}, "private": {Redirects: []string{redirect}, Scopes: []string{"read"}, SecretDigest: store.Digest("secret")}},
		Sessions: exchange.Verifier{Keys: &exchange.JWKS{URL: jwks.URL}, Issuer: "identity", Audience: "session"},
		DPoP:     dpop.Verifier{Store: mem}, Exchange: exchange.Service{Issuer: exchange.Issuer{Name: origin, Signer: signer}}}
	handler := srv.Handler()
	session := testutil.Access(signer, "identity", "tenant", "user", "session", "session", nil, nil)
	const rawDetails = `[{"type":"inventory","actions":["read"],"identifier":"inventory-1","filter":{"revisions":[1,2],"archived":false}}]`
	form := url.Values{"client_id": {"public"}, "redirect_uri": {redirect}, "state": {"original"}, "response_type": {"code"}, "code_challenge": {store.Digest(verifier)}, "code_challenge_method": {"S256"}, "scope": {"read"}, "authorization_details": {rawDetails}}
	form.Set("code_challenge_method", "plain")
	if w := post(handler, "/oauth/par", form, ""); w.Code != 400 {
		t.Fatalf("invalid PKCE accepted: %d %s", w.Code, w.Body)
	}
	form.Set("code_challenge_method", "S256")
	form.Set("client_id", "private")
	if w := post(handler, "/oauth/par", form, ""); w.Code != 401 {
		t.Fatalf("anonymous confidential client: %d %s", w.Code, w.Body)
	}
	form.Del("client_id")
	basic := httptest.NewRequest("POST", origin+"/oauth/par", strings.NewReader(form.Encode()))
	basic.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	basic.SetBasicAuth("private", "secret")
	basicResult := httptest.NewRecorder()
	handler.ServeHTTP(basicResult, basic)
	if basicResult.Code != 201 {
		t.Fatalf("confidential PAR: %d %s", basicResult.Code, basicResult.Body)
	}
	form.Set("client_id", "public")
	pushed := post(handler, "/oauth/par", form, "")
	var ref struct {
		URI string `json:"request_uri"`
		TTL int    `json:"expires_in"`
	}
	if err := json.Unmarshal(pushed.Body.Bytes(), &ref); err != nil || pushed.Code != 201 || !strings.HasPrefix(ref.URI, "urn:ietf:params:oauth:request_uri:") || ref.TTL != 60 || pushed.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("PAR response: %d %s (%v)", pushed.Code, pushed.Body, err)
	}
	authorize := func(p url.Values, loggedIn bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", origin+"/oauth/authorize?"+p.Encode(), nil)
		if loggedIn {
			req.AddCookie(&http.Cookie{Name: "__Host-bastion_session", Value: session})
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	front := url.Values{"request_uri": {ref.URI}, "client_id": {"public"}}
	if w := authorize(front, false); w.Code != 401 {
		t.Fatalf("unauthenticated authorize: %d %s", w.Code, w.Body)
	}
	front.Set("client_id", "private")
	if w := authorize(front, true); w.Code != 400 {
		t.Fatalf("wrong client: %d %s", w.Code, w.Body)
	}
	front.Set("client_id", "public")
	front.Set("state", "replacement")
	if w := authorize(front, true); w.Code != 400 {
		t.Fatalf("front-channel override: %d %s", w.Code, w.Body)
	}
	front.Del("state")
	var winners atomic.Int32
	pages := make(chan string, 24)
	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			w := authorize(front, true)
			if w.Code == 200 {
				winners.Add(1)
				pages <- w.Body.String()
			} else if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_request_uri") {
				t.Errorf("authorize: %d %s", w.Code, w.Body)
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("%d accepted PAR redemptions", winners.Load())
	}
	page := <-pages
	if !strings.Contains(page, "Authorization details") || !strings.Contains(page, "inventory-1") {
		t.Fatalf("details missing from consent: %s", page)
	}
	hidden := regexp.MustCompile(`name="([^"]+)" value="([^"]*)"`)
	consentForm := make(url.Values)
	for _, match := range hidden.FindAllStringSubmatch(page, -1) {
		consentForm.Set(match[1], html.UnescapeString(match[2]))
	}
	consentForm.Set("decision", "approve")
	consent := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", origin+"/oauth/authorize", strings.NewReader(consentForm.Encode()))
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "__Host-bastion_session", Value: session})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	consentForm.Set("authorization_details", strings.Replace(rawDetails, "inventory-1", "inventory-2", 1))
	if w := consent(); w.Code != 400 {
		t.Fatalf("tampered consent: %d %s", w.Code, w.Body)
	}
	consentForm.Set("authorization_details", rawDetails)
	approved := consent()
	callback, err := url.Parse(approved.Header().Get("Location"))
	if err != nil || approved.Code != 303 || callback.Query().Get("state") != "original" || callback.Query().Get("code") == "" {
		t.Fatalf("consent: %d %s", approved.Code, approved.Header().Get("Location"))
	}
	tokenForm := url.Values{"grant_type": {"authorization_code"}, "code": {callback.Query().Get("code")}, "client_id": {"public"}, "redirect_uri": {redirect}, "code_verifier": {strings.Repeat("x", 43)}}
	redeem := func(p url.Values) *httptest.ResponseRecorder {
		proof := testutil.Proof(proofSigner, "POST", origin+"/oauth/token", "", store.Secret(), time.Now())
		return post(handler, "/oauth/token", p, proof)
	}
	if w := redeem(tokenForm); w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_grant") {
		t.Fatalf("unbound verifier: %d %s", w.Code, w.Body)
	}
	tokenForm.Set("code_verifier", verifier)
	expected, err := exchange.ParseDetails(rawDetails)
	if err != nil {
		t.Fatal(err)
	}
	checkToken := func(w *httptest.ResponseRecorder) string {
		t.Helper()
		var response struct {
			Details exchange.Details `json:"authorization_details"`
			Access  string           `json:"access_token"`
			Refresh string           `json:"refresh_token"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); w.Code != 200 || err != nil || !reflect.DeepEqual(response.Details, expected) {
			t.Fatalf("token response: %d %s (%v)", w.Code, w.Body, err)
		}
		token, err := jwt.ParseSigned(response.Access, joseutil.Algorithms)
		if err != nil {
			t.Fatal(err)
		}
		var claims exchange.Claims
		if err := token.Claims(keys.Public, &claims); err != nil || !reflect.DeepEqual(claims.AuthorizationDetails, expected) {
			t.Fatalf("token claims: %+v (%v)", claims, err)
		}
		return response.Refresh
	}
	refresh := checkToken(redeem(tokenForm))
	checkToken(redeem(url.Values{"grant_type": {"refresh_token"}, "client_id": {"public"}, "refresh_token": {refresh}}))
}
