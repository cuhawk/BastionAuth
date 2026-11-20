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
)

type Client struct {
	Redirects    []string
	Scopes       []string
	SecretDigest string
}

type Server struct {
	Tenant, Origin, Audience string
	Clients                  map[string]Client
	Store                    store.Store
	Sessions                 exchange.Verifier
	DPoP                     dpop.Verifier
	Exchange                 exchange.Service
}

func (s Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth/authorize", s.authorize)
	mux.HandleFunc("POST /oauth/authorize", s.authorize)
	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("POST /oauth/grant/revoke", s.revoke)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
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

var authorizationFields = []string{"client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method", "scope", "state", "dpop_jkt"}

func consentBinding(session string, values url.Values) string {
	fields := url.Values{}
	for _, field := range authorizationFields {
		fields.Set(field, values.Get(field))
	}
	mac := hmac.New(sha256.New, []byte(session))
	mac.Write([]byte("bastionauth-consent-v1:" + fields.Encode()))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

var consentPage = template.Must(template.New("consent").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Authorize application</title>
<h1>Authorize {{.Client}}</h1><p>Requested permissions: {{.Scope}}</p>
<form action="/oauth/authorize" method="post">{{range $key,$value := .Fields}}<input type="hidden" name="{{$key}}" value="{{$value}}">{{end}}
<button name="decision" value="approve">Approve</button><button name="decision" value="deny">Deny</button></form></html>`))

func (s Server) authorize(w http.ResponseWriter, r *http.Request) {
	p, ok := parameters(w, r)
	client, registered := s.Clients[p.Get("client_id")]
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(p.Get("code_challenge"))
	state := p.Get("state")
	if !ok || !registered || !slices.Contains(client.Redirects, p.Get("redirect_uri")) || p.Get("response_type") != "code" || p.Get("code_challenge_method") != "S256" || err != nil || len(challenge) != 32 || len(p.Get("code_challenge")) != 43 || state == "" || len(state) > 1024 {
		failure(w, 400, "invalid_request")
		return
	}
	scopes, err := exchange.Scopes(p.Get("scope"))
	if err != nil || !allowed(scopes, client.Scopes) {
		failure(w, 400, "invalid_scope")
		return
	}
	user, session, err := s.session(r)
	if err != nil {
		failure(w, 401, "login_required")
		return
	}
	if r.Method == http.MethodGet {
		fields := make(map[string]string)
		for _, key := range authorizationFields {
			fields[key] = p.Get(key)
		}
		fields["consent_binding"] = consentBinding(session, p)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		_ = consentPage.Execute(w, struct {
			Client, Scope string
			Fields        map[string]string
		}{p.Get("client_id"), p.Get("scope"), fields})
		return
	}
	if r.Header.Get("Origin") != s.Origin || !equal(p.Get("consent_binding"), consentBinding(session, p)) || (p.Get("decision") != "approve" && p.Get("decision") != "deny") {
		failure(w, 400, "invalid_request")
		return
	}
	redirect, err := url.Parse(p.Get("redirect_uri"))
	if err != nil {
		failure(w, 400, "invalid_request")
		return
	}
	q := redirect.Query()
	q.Set("state", state)
	if p.Get("decision") == "deny" {
		q.Set("error", "access_denied")
	} else {
		code := store.Secret()
		c := store.Credential{User: user, Client: p.Get("client_id"), Kind: "authorization_code", Redirect: p.Get("redirect_uri"), Challenge: p.Get("code_challenge"), Scope: strings.Join(scopes, " "), JKT: p.Get("dpop_jkt"), Expires: time.Now().Add(2 * time.Minute)}
		if c.JKT != "" {
			digest, err := base64.RawURLEncoding.Strict().DecodeString(c.JKT)
			if err != nil || len(digest) != 32 {
				failure(w, 400, "invalid_request")
				return
			}
		}
		if err := s.Store.Consent(r.Context(), s.Tenant, store.Digest(code), c); err != nil {
			failure(w, 500, "server_error")
			return
		}
		q.Set("code", code)
	}
	redirect.RawQuery = q.Encode()
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

func (s Server) authenticate(r *http.Request, p url.Values) (string, bool) {
	if len(r.Header.Values("Authorization")) > 1 {
		return "", false
	}
	name, secret, basic := r.BasicAuth()
	if basic {
		var err error
		name, err = url.QueryUnescape(name)
		if err != nil {
			return "", false
		}
		secret, err = url.QueryUnescape(secret)
		if err != nil {
			return "", false
		}
		c, ok := s.Clients[name]
		return name, ok && c.SecretDigest != "" && !p.Has("client_secret") && !p.Has("client_id") && equal(store.Digest(secret), c.SecretDigest)
	}
	name = p.Get("client_id")
	c, ok := s.Clients[name]
	return name, ok && c.SecretDigest == "" && len(r.Header.Values("Authorization")) == 0 && !p.Has("client_secret")
}
func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (s Server) token(w http.ResponseWriter, r *http.Request) {
	p, ok := parameters(w, r)
	if !ok {
		failure(w, 400, "invalid_request")
		return
	}
	client, authenticated := s.authenticate(r, p)
	if !authenticated {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
		failure(w, 401, "invalid_client")
		return
	}
	grant := p.Get("grant_type")
	if grant != "authorization_code" && grant != "refresh_token" && grant != exchange.GrantType {
		failure(w, 400, "unsupported_grant_type")
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
		access, err = s.Exchange.Issuer.Mint(s.Tenant, c.User, s.Audience, c.Scope, jkt, nil, time.Now().Add(lifetime))
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
		respond(w, 200, map[string]any{"access_token": access, "token_type": "DPoP", "refresh_token": refresh, "expires_in": int(lifetime.Seconds()), "scope": scope})
	}
}

func (s Server) exchange(w http.ResponseWriter, r *http.Request, p url.Values, client, jkt string) {
	if s.Clients[client].SecretDigest == "" {
		failure(w, 400, "access_denied")
		return
	}
	if p.Get("subject_token") == "" || p.Get("actor_token") == "" || p.Get("subject_token_type") != exchange.AccessType || p.Get("actor_token_type") != exchange.AccessType || (p.Has("requested_token_type") && p.Get("requested_token_type") != exchange.AccessType) || p.Has("resource") || p.Get("audience") == "" {
		failure(w, 400, "invalid_request")
		return
	}
	result, err := s.Exchange.Exchange(r.Context(), s.Tenant, client, p.Get("subject_token"), p.Get("actor_token"), p.Get("audience"), p.Get("scope"), jkt)
	switch {
	case errors.Is(err, exchange.ErrScope):
		failure(w, 400, "invalid_scope")
	case errors.Is(err, exchange.ErrDenied):
		failure(w, 400, "access_denied")
	case err != nil:
		failure(w, 500, "server_error")
	default:
		respond(w, 200, map[string]any{"access_token": result.AccessToken, "issued_token_type": exchange.AccessType, "token_type": "DPoP", "expires_in": max(0, int(time.Until(result.ExpiresAt).Seconds())), "scope": result.Scope})
	}
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
	_, registered := s.Clients[p.Get("client_id")]
	if !ok || !registered || r.Header.Get("Origin") != s.Origin {
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
