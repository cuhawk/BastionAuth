package oauth

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/cuhawk/BastionAuth/internal/store"
)

const pushedRequestPrefix = "urn:ietf:params:oauth:request_uri:"
const pushedSignedMarker = "_signed_request_object"
const pushedRequestTTL = 60 * time.Second

func (s Server) pushAuthorization(w http.ResponseWriter, r *http.Request) {
	p, ok := parameters(w, r)
	if !ok {
		failure(w, 400, "invalid_request")
		return
	}
	for key := range p {
		if key != "request" && key != "client_assertion" && key != "client_assertion_type" && !slices.Contains(authorizationFields, key) {
			failure(w, 400, "invalid_request")
			return
		}
	}
	id, client, authenticated := s.authenticate(w, r, p, "par")
	if !authenticated {
		return
	}
	var identity signedIdentity
	if p.Has("request") {
		if len(p) != 1+countAuthenticationFields(p) {
			failure(w, 400, "invalid_request")
			return
		}
		var err error
		p, identity, err = s.requestObject(p.Get("request"), id, client)
		if err != nil {
			failure(w, 400, "invalid_request_object")
			return
		}
	} else if client.RequireJAR {
		failure(w, 400, "invalid_request_object")
		return
	}
	p.Del("client_assertion")
	p.Del("client_assertion_type")
	p.Set("client_id", id)
	if _, _, code := validateAuthorization(p, client); code != "" {
		failure(w, 400, code)
		return
	}
	now := time.Now()
	expires := now.Add(pushedRequestTTL)
	if identity.id != "" {
		if status, code := s.claimRequestObject(r.Context(), identity); code != "" {
			failure(w, status, code)
			return
		}
		p.Set(pushedSignedMarker, "1")
		if identity.expires.Before(expires) {
			expires = identity.expires
		}
	}
	secret := store.Secret()
	if err := s.Store.SavePushedRequest(r.Context(), s.Tenant, store.Digest(secret), store.PushedRequest{
		Client: id, Form: p.Encode(), Expires: expires,
	}); err != nil {
		failure(w, 500, "server_error")
		return
	}
	respond(w, http.StatusCreated, struct {
		URI     string `json:"request_uri"`
		Expires int    `json:"expires_in"`
	}{pushedRequestPrefix + secret, int((expires.Sub(now) + time.Second - 1) / time.Second)})
}

func countAuthenticationFields(p url.Values) int {
	count := 0
	for _, field := range []string{"client_id", "client_assertion", "client_assertion_type"} {
		if p.Has(field) {
			count++
		}
	}
	return count
}

func (s Server) takeAuthorization(r *http.Request, p url.Values) (url.Values, string, string, int, string) {
	secret, ok := strings.CutPrefix(p.Get("request_uri"), pushedRequestPrefix)
	if !ok || !validDigest(secret) || r.Method != http.MethodGet || len(p) != 2 || p.Get("client_id") == "" {
		return nil, "", "", 400, "invalid_request_uri"
	}
	user, session, err := s.session(r)
	if err != nil {
		return nil, "", "", 401, "login_required"
	}
	form, err := s.Store.TakePushedRequest(r.Context(), s.Tenant, p.Get("client_id"), store.Digest(secret))
	if errors.Is(err, store.ErrInvalid) {
		return nil, "", "", 400, "invalid_request_uri"
	}
	if err != nil {
		return nil, "", "", 500, "server_error"
	}
	values, err := url.ParseQuery(form)
	if err != nil {
		return nil, "", "", 500, "server_error"
	}
	return values, user, session, 0, ""
}
