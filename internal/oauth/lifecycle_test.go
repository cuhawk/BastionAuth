package oauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cuhawk/BastionAuth/internal/dpop"
	"github.com/cuhawk/BastionAuth/internal/exchange"
	"github.com/cuhawk/BastionAuth/internal/oauth"
	"github.com/cuhawk/BastionAuth/internal/store"
	"github.com/cuhawk/BastionAuth/internal/testutil"
)

func TestTokenLifecycle(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant"
	const audience = "https://resource.example.test/api/"
	keys := testutil.NewKeys()
	jwks := keys.JWKS()
	defer jwks.Close()
	proofSigner := testutil.NewKeys().Signer("dpop+jwt", true)
	mem := store.NewMemory()
	proofs := dpop.Verifier{Store: mem}
	confidential := oauth.Client{SecretDigest: store.Digest("secret")}
	srv := oauth.Server{
		Tenant: tenant, Origin: origin, Audience: audience, Store: mem, DPoP: proofs,
		Clients:         map[string]oauth.Client{"owner": confidential, "resource": confidential, "other": confidential, "public": {}},
		ResourceServers: map[string][]string{"resource": {audience}, "other": {"another-audience"}},
		Exchange:        exchange.Service{Issuer: exchange.Issuer{Name: origin + "/issuer/", Signer: keys.Signer("at+jwt", false)}},
	}
	handler := srv.Handler()
	submit := func(path, client string, p url.Values, proof string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", origin+path, strings.NewReader(p.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if client != "" {
			req.SetBasicAuth(client, "secret")
		}
		if proof != "" {
			req.Header.Set("DPoP", proof)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	addCode := func() string {
		code := store.Secret()
		err := mem.Consent(ctx, tenant, store.Digest(code), store.Credential{
			User: "subject", Client: "owner", Kind: "authorization_code", Redirect: redirect,
			Challenge: store.Digest(verifier), Scope: "read", Expires: time.Now().Add(time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
		return code
	}
	codeForm := func(code string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier}}
	}
	tokenRequest := func(p url.Values) *httptest.ResponseRecorder {
		return submit("/oauth/token", "owner", p, testutil.Proof(proofSigner, "POST", origin+"/oauth/token", "", store.Secret(), time.Now()))
	}
	mint := func(p url.Values) map[string]string {
		t.Helper()
		w := tokenRequest(p)
		var issued struct {
			Access  string `json:"access_token"`
			Refresh string `json:"refresh_token"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &issued) != nil || issued.Access == "" || issued.Refresh == "" {
			t.Fatalf("issuance: %d %s", w.Code, w.Body)
		}
		return map[string]string{"access": issued.Access, "refresh": issued.Refresh}
	}
	form := func(token string) url.Values { return url.Values{"token": {token}} }
	first := mint(codeForm(addCode()))
	pending := addCode()
	second := mint(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first["refresh"]}})
	access := second["access"]
	verify := func() (exchange.Claims, error) {
		v := exchange.Verifier{Keys: &exchange.JWKS{URL: jwks.URL}, Issuer: origin + "/issuer/", Audience: audience}
		proof := testutil.Proof(proofSigner, "GET", audience, access, store.Secret(), time.Now())
		return proofs.VerifyAccess(ctx, v, tenant, access, proof, "GET", audience)
	}
	claims, err := verify()
	if err != nil {
		t.Fatal(err)
	}
	if w := submit("/oauth/revoke", "", url.Values{"client_id": {"public"}, "token": {access}}, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("missing authentication: %d", w.Code)
	}
	if w := submit("/oauth/introspect", "owner", form(access), ""); w.Code != http.StatusForbidden {
		t.Fatalf("non-resource introspection: %d", w.Code)
	}
	if w := submit("/oauth/revoke", "other", form(access), ""); w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("foreign revocation: %d %s", w.Code, w.Body)
	}
	var info struct {
		Active bool
		Scope  string
		Sub    string
		Client string `json:"client_id"`
		Exp    int64
		CNF    exchange.Confirmation
	}
	w := submit("/oauth/introspect", "resource", form(access), "")
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &info) != nil ||
		!info.Active || info.Scope != "read" || info.Sub != "subject" || info.Client != "owner" ||
		info.Exp != claims.Expiry.Time().Unix() || info.CNF.JKT != claims.CNF.JKT {
		t.Fatalf("active response: %d %s", w.Code, w.Body)
	}
	inactive := func(client, token string) {
		t.Helper()
		w := submit("/oauth/introspect", client, form(token), "")
		if w.Code != http.StatusOK || w.Body.String() != "{\"active\":false}\n" {
			t.Fatalf("inactive response: %d %s", w.Code, w.Body)
		}
	}
	inactive("other", access)
	inactive("resource", "unknown")
	// A refresh token rotated by a concurrent request can still revoke its grant.
	w = submit("/oauth/revoke", "owner", url.Values{"token": {first["refresh"]}, "token_type_hint": {"access_token"}}, "")
	if w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	inactive("resource", first["access"])
	inactive("resource", access)
	if _, err := verify(); err == nil {
		t.Fatal("revoked access token passed DPoP validation")
	}
	for _, p := range []url.Values{codeForm(pending), {"grant_type": {"refresh_token"}, "refresh_token": {second["refresh"]}}} {
		if w := tokenRequest(p); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_grant") {
			t.Fatalf("stale grant credential: %d %s", w.Code, w.Body)
		}
	}
	fresh := mint(codeForm(addCode()))
	if w := submit("/oauth/revoke", "owner", form(access), ""); w.Code != http.StatusOK {
		t.Fatalf("repeated revocation: %d", w.Code)
	}
	if w := submit("/oauth/introspect", "resource", form(fresh["access"]), ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"active":true`) {
		t.Fatalf("old token revoked newly consented grant: %d %s", w.Code, w.Body)
	}
	if w := submit("/oauth/revoke", "owner", form(fresh["access"]), ""); w.Code != http.StatusOK {
		t.Fatalf("access-token revocation: %d", w.Code)
	}
	inactive("resource", fresh["access"])

	for path, expected := range map[string]string{
		"/.well-known/oauth-authorization-server/issuer": origin + "/oauth/revoke",
		"/.well-known/oauth-protected-resource/api/":     audience,
		"/.well-known/oauth-protected-resource":          audience,
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", origin+path, nil))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), expected) {
			t.Fatalf("metadata %s: %d %s", path, w.Code, w.Body)
		}
	}
}

func TestAuthorizationRedirectValidation(t *testing.T) {
	for _, suffix := range []string{"#", "#state", "?%73tate=x", "?dpop_jkt=x", "?error_uri=x", "?%xx"} {
		if oauth.ValidRedirectURI(redirect+suffix, false) {
			t.Errorf("accepted reserved or malformed redirect %q", redirect+suffix)
		}
	}
	if !oauth.ValidRedirectURI(redirect+"?custom=value", false) {
		t.Fatal("rejected unrelated callback query parameter")
	}
}
