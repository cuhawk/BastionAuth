package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/cuhawk/BastionAuth/internal/dpop"
	"github.com/cuhawk/BastionAuth/internal/exchange"
	"github.com/cuhawk/BastionAuth/internal/store"
	"github.com/go-jose/go-jose/v4"
)

type Client struct {
	Redirects     []string
	Scopes        []string
	SecretDigest  string
	JWTKeys       []jose.JSONWebKey
	PrivateKeyJWT bool
	RequireJAR    bool
	RequestURIs   []string
}

type Server struct {
	Tenant, Origin, Audience string
	Resource                 string
	Clients                  map[string]Client
	ResourceServers          map[string][]string
	CIMD                     *CIMDResolver
	CIMDScopes               []string
	Store                    store.Store
	Sessions                 exchange.Verifier
	DPoP                     dpop.Verifier
	Exchange                 exchange.Service
	requestObjects           *http.Client
}

func (s Server) Handler() http.Handler {
	if s.requestObjects == nil {
		s.requestObjects = newPublicHTTPSClient()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.metadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.resourceMetadata)
	registerMetadataPath(mux, "/.well-known/oauth-authorization-server", s.Exchange.Issuer.Name, true, s.metadata)
	registerMetadataPath(mux, "/.well-known/oauth-protected-resource", s.resourceIdentifier(), false, s.resourceMetadata)
	mux.HandleFunc("GET /oauth/authorize", s.authorize)
	mux.HandleFunc("POST /oauth/authorize", s.authorize)
	mux.HandleFunc("POST /oauth/par", s.pushAuthorization)
	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("POST /oauth/revoke", s.revokeToken)
	mux.HandleFunc("POST /oauth/introspect", s.introspect)
	mux.HandleFunc("POST /oauth/grant/revoke", s.revoke)
	handler := instrument(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		handler.ServeHTTP(w, r)
	})
}

func (s Server) metadata(w http.ResponseWriter, _ *http.Request) {
	respond(w, http.StatusOK, map[string]any{
		"issuer":                 s.Exchange.Issuer.Name,
		"authorization_endpoint": s.Origin + "/oauth/authorize",
		"revocation_endpoint":    s.Origin + "/oauth/revoke",
		"revocation_endpoint_auth_methods_supported":               confidentialAuthMethods,
		"revocation_endpoint_auth_signing_alg_values_supported":    signedAlgorithms,
		"introspection_endpoint":                                   s.Origin + "/oauth/introspect",
		"introspection_endpoint_auth_methods_supported":            confidentialAuthMethods,
		"introspection_endpoint_auth_signing_alg_values_supported": signedAlgorithms,
		"dpop_signing_alg_values_supported":                        dpop.SigningAlgorithms(),
		"token_endpoint":                                           s.Origin + "/oauth/token",
		"jwks_uri":                                                 s.Origin + "/.well-known/jwks.json",
		"pushed_authorization_request_endpoint":                    s.Origin + "/oauth/par",
		"client_id_metadata_document_supported":                    s.CIMD != nil,
		"response_modes_supported":                                 []string{"query"},
		"response_types_supported":                                 []string{"code"},
		"grant_types_supported":                                    []string{"authorization_code", "refresh_token", exchange.GrantType},
		"code_challenge_methods_supported":                         []string{"S256"},
		"token_endpoint_auth_methods_supported":                    []string{"none", "client_secret_basic", "private_key_jwt"},
		"request_parameter_supported":                              true,
		"request_uri_parameter_supported":                          true,
		"require_request_uri_registration":                         true,
		"request_object_signing_alg_values_supported":              signedAlgorithms,
		"token_endpoint_auth_signing_alg_values_supported":         signedAlgorithms,
	})
}

func failure(w http.ResponseWriter, status int, code string) {
	respond(w, status, map[string]string{"error": code})
}
func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func parameters(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	var p url.Values
	if r.Method == http.MethodGet {
		var err error
		p, err = url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			return nil, false
		}
	} else {
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
			return nil, false
		}
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		if err = r.ParseForm(); err != nil {
			return nil, false
		}
		p = r.PostForm
	}
	for _, vs := range p {
		if len(vs) != 1 {
			return nil, false
		}
	}
	return p, true
}

func (s Server) session(r *http.Request) (user, token string, err error) {
	cookie, err := r.Cookie("__Host-bastion_session")
	if err != nil {
		return "", "", err
	}
	c, err := s.Sessions.Verify(r.Context(), cookie.Value, s.Tenant)
	return c.Subject, cookie.Value, err
}

var authorizationFields = []string{"client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method", "scope", "state", "dpop_jkt", "authorization_details"}

func consentBinding(session string, values url.Values) string {
	fields := url.Values{}
	for _, field := range authorizationFields {
		fields.Set(field, values.Get(field))
	}
	if values.Has("signed_consent") {
		fields.Set("signed_consent", values.Get("signed_consent"))
	}
	mac := hmac.New(sha256.New, []byte(session))
	mac.Write([]byte("bastionauth-consent-v1:" + fields.Encode()))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

var consentPage = template.Must(template.New("consent").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Authorize application</title>
<h1>Authorize {{.Client}}</h1><p>Requested permissions: {{.Scope}}</p>{{if .Details}}<h2>Authorization details</h2><pre>{{.Details}}</pre>{{end}}
<form action="/oauth/authorize" method="post">{{range $key,$value := .Fields}}<input type="hidden" name="{{$key}}" value="{{$value}}">{{end}}
<button name="decision" value="approve">Approve</button><button name="decision" value="deny">Deny</button></form></html>`))

func validDigest(raw string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	return len(raw) == 43 && err == nil && len(decoded) == 32
}

func validateAuthorization(p url.Values, client Client) ([]string, exchange.Details, string) {
	state := p.Get("state")
	if p.Get("response_type") != "code" || p.Get("code_challenge_method") != "S256" ||
		!validDigest(p.Get("code_challenge")) || state == "" || len(state) > 1024 ||
		(p.Get("dpop_jkt") != "" && !validDigest(p.Get("dpop_jkt"))) {
		return nil, nil, "invalid_request"
	}
	if !metadataRedirect(p.Get("redirect_uri")) || !slices.Contains(client.Redirects, p.Get("redirect_uri")) {
		return nil, nil, "invalid_request"
	}
	var details exchange.Details
	if raw := p.Get("authorization_details"); p.Has("authorization_details") {
		var err error
		details, err = exchange.ParseDetails(raw)
		if err != nil {
			return nil, nil, exchange.ErrDetails.Error()
		}
	}
	var scopes []string
	if p.Get("scope") != "" || details == nil {
		var err error
		scopes, err = exchange.Scopes(p.Get("scope"))
		if err != nil || !allowed(scopes, client.Scopes) {
			return nil, nil, "invalid_scope"
		}
	}
	return scopes, details, ""
}

func (s Server) authorize(w http.ResponseWriter, r *http.Request) {
	p, ok := parameters(w, r)
	if !ok || r.URL.Fragment != "" {
		failure(w, 400, "invalid_request")
		return
	}
	var user, session string
	var identity signedIdentity
	var signedConsent bool
	switch {
	case p.Has("request") || (p.Has("request_uri") && !strings.HasPrefix(p.Get("request_uri"), pushedRequestPrefix)):
		var code string
		p, identity, code = s.frontChannelJAR(r, p)
		if code != "" {
			failure(w, 400, code)
			return
		}
	case p.Has("request_uri"):
		var status int
		var code string
		p, user, session, status, code = s.takeAuthorization(r, p)
		if code != "" {
			failure(w, status, code)
			return
		}
		signedConsent = p.Has(pushedSignedMarker)
		p.Del(pushedSignedMarker)
	}
	client, name, ok := s.resolveClient(r.Context(), p.Get("client_id"))
	if !ok {
		failure(w, 400, "invalid_request")
		return
	}
	if client.RequireJAR && r.Method == http.MethodGet && identity.id == "" && !signedConsent {
		failure(w, 400, "invalid_request_object")
		return
	}
	scopes, details, code := validateAuthorization(p, client)
	if code != "" {
		failure(w, 400, code)
		return
	}
	if session == "" {
		var err error
		user, session, err = s.session(r)
		if err != nil {
			failure(w, 401, "login_required")
			return
		}
	}
	if identity.id != "" {
		if status, code := s.claimRequestObject(r.Context(), identity); code != "" {
			failure(w, status, code)
			return
		}
	}
	var encodedDetails string
	if details != nil {
		encoded, err := json.Marshal(details)
		if err != nil {
			failure(w, 500, "server_error")
			return
		}
		encodedDetails = string(encoded)
		p.Set("authorization_details", encodedDetails)
	}
	if r.Method == http.MethodGet {
		fields := make(map[string]string)
		for _, key := range authorizationFields {
			if p.Has(key) {
				fields[key] = p.Get(key)
			}
		}
		if signedConsent || identity.id != "" {
			nonce := store.Secret()
			p.Set("signed_consent", nonce)
			binding := consentBinding(session, p)
			err := s.Store.SavePushedRequest(r.Context(), s.Tenant, signedConsentDigest(nonce, binding), store.PushedRequest{
				Client: p.Get("client_id"), Expires: time.Now().Add(maxSignedJWT),
			})
			if err != nil {
				failure(w, 500, "server_error")
				return
			}
			fields["signed_consent"] = nonce
		} else {
			p.Del("signed_consent")
		}
		fields["consent_binding"] = consentBinding(session, p)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		_ = consentPage.Execute(w, struct {
			Client, Scope, Details string
			Fields                 map[string]string
		}{name, p.Get("scope"), encodedDetails, fields})
		return
	}
	if r.Header.Get("Origin") != s.Origin || !equal(p.Get("consent_binding"), consentBinding(session, p)) || (p.Get("decision") != "approve" && p.Get("decision") != "deny") {
		failure(w, 400, "invalid_request")
		return
	}
	if client.RequireJAR || p.Has("signed_consent") {
		nonce := p.Get("signed_consent")
		if !validDigest(nonce) {
			failure(w, 400, "invalid_request")
			return
		}
		_, err := s.Store.TakePushedRequest(r.Context(), s.Tenant, p.Get("client_id"), signedConsentDigest(nonce, p.Get("consent_binding")))
		if errors.Is(err, store.ErrInvalid) {
			failure(w, 400, "invalid_request")
			return
		}
		if err != nil {
			failure(w, 500, "server_error")
			return
		}
	}
	redirect, err := url.Parse(p.Get("redirect_uri"))
	if err != nil {
		failure(w, 400, "invalid_request")
		return
	}
	q := url.Values{}
	q.Set("state", p.Get("state"))
	if p.Get("decision") == "deny" {
		q.Set("error", "access_denied")
	} else {
		code := store.Secret()
		c := store.Credential{User: user, Client: p.Get("client_id"), Kind: "authorization_code", Redirect: p.Get("redirect_uri"), Challenge: p.Get("code_challenge"), Scope: strings.Join(scopes, " "), AuthorizationDetails: encodedDetails, JKT: p.Get("dpop_jkt"), Expires: time.Now().Add(2 * time.Minute)}
		if err := s.Store.Consent(r.Context(), s.Tenant, store.Digest(code), c); err != nil {
			failure(w, 500, "server_error")
			return
		}
		q.Set("code", code)
	}
	if redirect.RawQuery != "" {
		redirect.RawQuery += "&"
	}
	redirect.RawQuery += q.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
}

func allowed(requested, granted []string) bool {
	for _, scope := range requested {
		if !slices.Contains(granted, scope) {
			return false
		}
	}
	return true
}

func (s Server) authenticate(w http.ResponseWriter, r *http.Request, p url.Values, realm string) (string, Client, bool) {
	if p.Has("client_assertion") || p.Has("client_assertion_type") {
		id, client, err := s.assertionClient(r, p)
		switch {
		case err == nil:
			return id, client, true
		case errors.Is(err, errSignedJWT):
			failure(w, 401, "invalid_client")
		default:
			failure(w, 500, "server_error")
		}
		return "", Client{}, false
	}
	id, client, ok := s.authenticateLegacy(r, p)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
		failure(w, 401, "invalid_client")
	}
	return id, client, ok
}

func (s Server) authenticateLegacy(r *http.Request, p url.Values) (string, Client, bool) {
	if len(r.Header.Values("Authorization")) > 1 {
		return "", Client{}, false
	}
	name, secret, basic := r.BasicAuth()
	if basic {
		var err error
		name, err = url.QueryUnescape(name)
		if err != nil {
			return "", Client{}, false
		}
		secret, err = url.QueryUnescape(secret)
		if err != nil {
			return "", Client{}, false
		}
		c, ok := s.Clients[name]
		return name, c, ok && !c.PrivateKeyJWT && c.SecretDigest != "" && !p.Has("client_secret") && !p.Has("client_id") && equal(store.Digest(secret), c.SecretDigest)
	}
	name = p.Get("client_id")
	if len(r.Header.Values("Authorization")) != 0 || p.Has("client_secret") {
		return "", Client{}, false
	}
	c, _, ok := s.resolveClient(r.Context(), name)
	return name, c, ok && c.SecretDigest == "" && !c.PrivateKeyJWT
}
func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (s Server) token(w http.ResponseWriter, r *http.Request) {
	p, ok := parameters(w, r)
	if !ok {
		failure(w, 400, "invalid_request")
		return
	}
	client, metadata, authenticated := s.authenticate(w, r, p, "token")
	if !authenticated {
		return
	}
	grant := p.Get("grant_type")
	if grant != "authorization_code" && grant != "refresh_token" && grant != exchange.GrantType {
		failure(w, 400, "unsupported_grant_type")
		return
	}
	if grant != exchange.GrantType && p.Has("authorization_details") {
		failure(w, 400, exchange.ErrDetails.Error())
		return
	}
	if _, registered := s.Clients[client]; grant == "authorization_code" && !registered && !slices.Contains(metadata.Redirects, p.Get("redirect_uri")) {
		failure(w, 400, "invalid_grant")
		return
	}
	if len(r.Header.Values("DPoP")) != 1 {
		failure(w, 400, "invalid_dpop_proof")
		return
	}
	jkt, err := s.DPoP.Verify(r.Context(), s.Tenant, r.Header.Get("DPoP"), r.Method, s.Origin+"/oauth/token", "", "")
	if err != nil {
		if errors.Is(err, dpop.ErrProof) {
			failure(w, 400, "invalid_dpop_proof")
		} else {
			failure(w, 500, "server_error")
		}
		return
	}
	if grant == exchange.GrantType {
		s.exchange(w, r, p, client, jkt)
		return
	}
	old := p.Get("code")
	if grant == "refresh_token" {
		old = p.Get("refresh_token")
	}
	if old == "" {
		failure(w, 400, "invalid_request")
		return
	}
	refresh := store.Secret()
	var access, scope string
	var details exchange.Details
	const lifetime = 5 * time.Minute
	err = s.Store.Rotate(r.Context(), s.Tenant, store.Digest(old), store.Digest(refresh), func(c store.Credential) (store.Credential, error) {
		if c.Client != client || c.Kind != grant || !time.Now().Before(c.Expires) || (c.JKT != "" && !equal(c.JKT, jkt)) {
			return c, store.ErrInvalid
		}
		if grant == "authorization_code" {
			verifier := p.Get("code_verifier")
			if c.Redirect != p.Get("redirect_uri") || !validVerifier(verifier) || !equal(c.Challenge, store.Digest(verifier)) {
				return c, store.ErrInvalid
			}
			c.Expires = time.Now().Add(24 * time.Hour)
		}
		if grant == "refresh_token" && p.Has("scope") {
			requested, err := exchange.Scopes(p.Get("scope"))
			if err != nil || !allowed(requested, strings.Split(c.Scope, " ")) {
				return c, exchange.ErrScope
			}
			c.Scope = strings.Join(requested, " ")
		}
		c.Kind = "refresh_token"
		c.JKT = jkt
		scope = c.Scope
		var err error
		if c.AuthorizationDetails != "" {
			details, err = exchange.ParseDetails(c.AuthorizationDetails)
			if err != nil {
				return c, err
			}
		}
		expiry := time.Now().Add(lifetime).Truncate(time.Second)
		var jti string
		access, jti, err = s.Exchange.Issuer.MintForClient(s.Tenant, c.User, client, s.Audience, c.Scope, jkt, nil, expiry, details)
		c.Access = &store.AccessToken{Digest: store.Digest(access), JTI: jti, User: c.User, Client: client,
			Audience: s.Audience, Scope: c.Scope, JKT: jkt, Expires: expiry}
		return c, err
	})
	switch {
	case errors.Is(err, store.ErrInvalid):
		failure(w, 400, "invalid_grant")
	case errors.Is(err, exchange.ErrScope):
		failure(w, 400, "invalid_scope")
	case err != nil:
		failure(w, 500, "server_error")
	default:
		tokenResponse(w, details, map[string]any{"access_token": access, "token_type": "DPoP", "refresh_token": refresh, "expires_in": int(lifetime.Seconds()), "scope": scope})
	}
}

func (s Server) exchange(w http.ResponseWriter, r *http.Request, p url.Values, client, jkt string) {
	if metadata := s.Clients[client]; metadata.SecretDigest == "" && !metadata.PrivateKeyJWT {
		failure(w, 400, "access_denied")
		return
	}
	if p.Get("subject_token") == "" || p.Get("actor_token") == "" || p.Get("subject_token_type") != exchange.AccessType || p.Get("actor_token_type") != exchange.AccessType || (p.Has("requested_token_type") && p.Get("requested_token_type") != exchange.AccessType) || p.Has("resource") || p.Get("audience") == "" {
		failure(w, 400, "invalid_request")
		return
	}
	var details exchange.Details
	if p.Has("authorization_details") {
		var err error
		details, err = exchange.ParseDetails(p.Get("authorization_details"))
		if err != nil {
			failure(w, 400, exchange.ErrDetails.Error())
			return
		}
	}
	result, err := s.Exchange.ExchangeWithDetails(r.Context(), s.Tenant, client, p.Get("subject_token"), p.Get("actor_token"), p.Get("audience"), p.Get("scope"), jkt, details)
	if err == nil {
		err = s.Store.SaveAccess(r.Context(), s.Tenant, store.AccessToken{
			Digest: store.Digest(result.AccessToken), JTI: result.JTI, User: result.Subject, Client: client,
			Audience: p.Get("audience"), Scope: result.Scope, JKT: jkt, Expires: result.ExpiresAt,
		})
	}
	switch {
	case errors.Is(err, exchange.ErrScope):
		failure(w, 400, "invalid_scope")
	case errors.Is(err, exchange.ErrDetails):
		failure(w, 400, exchange.ErrDetails.Error())
	case errors.Is(err, exchange.ErrDenied), errors.Is(err, store.ErrInvalid):
		failure(w, 400, "access_denied")
	case err != nil:
		failure(w, 500, "server_error")
	default:
		tokenResponse(w, result.AuthorizationDetails, map[string]any{"access_token": result.AccessToken, "issued_token_type": exchange.AccessType, "token_type": "DPoP", "expires_in": max(0, int(time.Until(result.ExpiresAt).Seconds())), "scope": result.Scope})
	}
}

func tokenResponse(w http.ResponseWriter, details exchange.Details, fields map[string]any) {
	if len(details) > 0 {
		fields["authorization_details"] = details
	}
	respond(w, http.StatusOK, fields)
}

func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, r := range v {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~", r)) {
			return false
		}
	}
	return true
}

func (s Server) RevokeGrant(ctx context.Context, userID, clientID string) error {
	return s.Store.Revoke(ctx, s.Tenant, userID, clientID)
}

func (s Server) revoke(w http.ResponseWriter, r *http.Request) {
	p, ok := parameters(w, r)
	id := p.Get("client_id")
	_, registered := s.Clients[id]
	if !ok || (!registered && (s.CIMD == nil || !metadataURL(id))) || r.Header.Get("Origin") != s.Origin {
		failure(w, 400, "invalid_request")
		return
	}
	user, _, err := s.session(r)
	if err != nil {
		failure(w, 401, "login_required")
		return
	}
	if err = s.RevokeGrant(r.Context(), user, p.Get("client_id")); err != nil {
		failure(w, 500, "server_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
