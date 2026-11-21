package oauth

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/cuhawk/BastionAuth/internal/dpop"
	"github.com/cuhawk/BastionAuth/internal/store"
)

var confidentialAuthMethods = []string{"client_secret_basic", "private_key_jwt"}

func (s Server) lifecycleRequest(w http.ResponseWriter, r *http.Request, realm string) (client, token string, ok bool) {
	p, valid := parameters(w, r)
	if !valid || p.Get("token") == "" {
		failure(w, http.StatusBadRequest, "invalid_request")
		return "", "", false
	}
	// Both endpoints require confidential authentication. A bare client_id
	// is identification only, so it must never reach client metadata resolution.
	if len(r.Header.Values("Authorization")) == 0 && !p.Has("client_assertion") && !p.Has("client_assertion_type") {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
		failure(w, http.StatusUnauthorized, "invalid_client")
		return "", "", false
	}
	client, _, ok = s.authenticate(w, r, p, realm)
	return client, p.Get("token"), ok
}

func (s Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	client, token, ok := s.lifecycleRequest(w, r, "revoke")
	if !ok {
		return
	}
	// Always search both supported token types, regardless of token_type_hint.
	if err := s.Store.RevokeToken(r.Context(), s.Tenant, client, store.Digest(token)); err != nil {
		failure(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s Server) introspect(w http.ResponseWriter, r *http.Request) {
	client, token, ok := s.lifecycleRequest(w, r, "introspect")
	if !ok {
		return
	}
	audiences := s.ResourceServers[client]
	if len(audiences) == 0 {
		failure(w, http.StatusForbidden, "access_denied")
		return
	}
	record, err := s.Store.LookupAccess(r.Context(), s.Tenant, store.Digest(token))
	if err != nil && !errors.Is(err, store.ErrInvalid) {
		failure(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	if err != nil || !slices.Contains(audiences, record.Audience) {
		respond(w, http.StatusOK, map[string]bool{"active": false})
		return
	}
	claims := map[string]any{
		"active": true, "scope": record.Scope, "sub": record.User,
		"client_id": record.Client, "exp": record.Expires.Unix(),
	}
	if record.JKT != "" {
		claims["cnf"] = map[string]string{"jkt": record.JKT}
	}
	respond(w, http.StatusOK, claims)
}

func registerMetadataPath(mux *http.ServeMux, prefix, identifier string, trimSlash bool, handler http.HandlerFunc) {
	u, ok := metadataIdentifierURL(identifier)
	if !ok {
		return
	}
	path := u.EscapedPath()
	if trimSlash || path == "/" {
		path = strings.TrimRight(path, "/")
	}
	if path == "" {
		return
	}
	if strings.HasSuffix(path, "/") {
		path += "{$}"
	}
	mux.HandleFunc("GET "+prefix+path, handler)
}

func metadataIdentifierURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	return u, err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil &&
		!strings.ContainsAny(raw, "#\\")
}

func (s Server) resourceIdentifier() string {
	if s.Resource != "" {
		return s.Resource
	}
	return s.Audience
}

func (s Server) resourceMetadata(w http.ResponseWriter, r *http.Request) {
	resource := s.resourceIdentifier()
	if _, ok := metadataIdentifierURL(resource); !ok {
		http.NotFound(w, r)
		return
	}
	respond(w, http.StatusOK, map[string]any{
		"resource": resource, "authorization_servers": []string{s.Exchange.Issuer.Name},
		"dpop_bound_access_tokens_required": true,
		"dpop_signing_alg_values_supported": dpop.SigningAlgorithms(),
	})
}
