package exchange

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cuhawk/BastionAuth/internal/joseutil"
	"github.com/cuhawk/BastionAuth/internal/store"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
const AccessType = "urn:ietf:params:oauth:token-type:access_token"

var ErrDenied = errors.New("access_denied")
var ErrScope = errors.New("invalid_scope")

type Actor struct {
	Subject string `json:"sub"`
	Issuer  string `json:"iss,omitempty"`
	Act     *Actor `json:"act,omitempty"`
}
type Confirmation struct {
	JKT string `json:"jkt"`
}
type Claims struct {
	jwt.Claims
	Tenant string        `json:"tenant_id"`
	Scope  string        `json:"scope"`
	Act    *Actor        `json:"act,omitempty"`
	MayAct *Actor        `json:"may_act,omitempty"`
	CNF    *Confirmation `json:"cnf,omitempty"`
}

type JWKS struct {
	URL       string
	Client    *http.Client
	mu        sync.Mutex
	keys      map[string]jose.JSONWebKey
	expires   time.Time
	refreshed time.Time
}

func (j *JWKS) key(ctx context.Context, kid, alg string) (any, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	key, found := j.keys[kid]
	if !now.Before(j.expires) || !found {
		if now.Sub(j.refreshed) < time.Second {
			return nil, ErrDenied
		}
		j.refreshed = now
		contextWithTimeout, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(contextWithTimeout, http.MethodGet, j.URL, nil)
		if err != nil {
			return nil, err
		}
		client := j.Client
		if client == nil {
			client = http.DefaultClient
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, ErrDenied
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024+1))
		if err != nil || len(data) > 256*1024 {
			return nil, ErrDenied
		}
		var jwks jose.JSONWebKeySet
		if err := json.Unmarshal(data, &jwks); err != nil {
			return nil, err
		}
		keys := make(map[string]jose.JSONWebKey)
		for _, candidate := range jwks.Keys {
			if candidate.KeyID == "" || !candidate.Valid() || !candidate.IsPublic() || (candidate.Use != "" && candidate.Use != "sig") {
				continue
			}
			if _, duplicate := keys[candidate.KeyID]; duplicate {
				return nil, ErrDenied
			}
			keys[candidate.KeyID] = candidate
		}
		j.keys, j.expires = keys, now.Add(time.Minute)
		key, found = keys[kid]
	}
	if !found || (key.Algorithm != "" && key.Algorithm != alg) || !joseutil.Matches(alg, key.Key) {
		return nil, ErrDenied
	}
	return key.Key, nil
}

type Verifier struct {
	Keys             *JWKS
	Issuer, Audience string
}

func (v Verifier) Verify(ctx context.Context, raw, tenant string) (Claims, error) {
	var c Claims
	if v.Keys == nil || len(raw) > 16384 || strings.Count(raw, ".") != 2 {
		return c, ErrDenied
	}
	token, err := jwt.ParseSigned(raw, joseutil.Algorithms)
	if err != nil || len(token.Headers) != 1 {
		return c, ErrDenied
	}
	h := token.Headers[0]
	if h.KeyID == "" || len(h.KeyID) > 256 || h.ExtraHeaders[jose.HeaderType] != "at+jwt" || h.JSONWebKey != nil {
		return c, ErrDenied
	}
	key, err := v.Keys.key(ctx, h.KeyID, h.Algorithm)
	if err != nil {
		return c, ErrDenied
	}
	if err = token.Claims(key, &c); err != nil {
		return c, ErrDenied
	}
	if err = c.ValidateWithLeeway(jwt.Expected{Issuer: v.Issuer, AnyAudience: jwt.Audience{v.Audience}, Time: time.Now()}, 0); err != nil || c.Expiry == nil || len(c.Audience) != 1 || c.Subject == "" || tenant == "" || c.Tenant != tenant {
		return c, ErrDenied
	}
	if c.CNF != nil && c.CNF.JKT == "" {
		return c, ErrDenied
	}
	return c, nil
}

type Issuer struct {
	Name   string
	Signer jose.Signer
}

func (i Issuer) Mint(tenant, subject, audience, scope, jkt string, act *Actor, expiry time.Time) (string, error) {
	c := Claims{Claims: jwt.Claims{Issuer: i.Name, Subject: subject, Audience: jwt.Audience{audience}, IssuedAt: jwt.NewNumericDate(time.Now()), Expiry: jwt.NewNumericDate(expiry), ID: store.Secret()}, Tenant: tenant, Scope: scope, Act: act}
	if jkt != "" {
		c.CNF = &Confirmation{JKT: jkt}
	}
	return jwt.Signed(i.Signer).Claims(c).Serialize()
}

type Service struct {
	Verifier Verifier
	Issuer   Issuer
	Targets  map[string][]string
}

type Result struct {
	AccessToken string
	Scope       string
	ExpiresAt   time.Time
}

func (s Service) Exchange(ctx context.Context, tenant, client, subjectToken, actorToken, audience, requested, jkt string) (Result, error) {
	subject, err := s.Verifier.Verify(ctx, subjectToken, tenant)
	if err != nil {
		return Result{}, ErrDenied
	}
	actor, err := s.Verifier.Verify(ctx, actorToken, tenant)
	if err != nil || actor.Subject != client || actor.Act != nil || subject.MayAct == nil || subject.MayAct.Act != nil || subject.MayAct.Subject != actor.Subject || (subject.MayAct.Issuer != "" && subject.MayAct.Issuer != actor.Issuer) {
		return Result{}, ErrDenied
	}
	for _, c := range []Claims{subject, actor} {
		if c.CNF != nil && c.CNF.JKT != jkt {
			return Result{}, ErrDenied
		}
	}
	ceiling, ok := s.Targets[audience]
	if !ok || audience == "" || jkt == "" {
		return Result{}, ErrDenied
	}
	subjectScopes, err := Scopes(subject.Scope)
	if err != nil {
		return Result{}, err
	}
	actorScopes, err := Scopes(actor.Scope)
	if err != nil {
		return Result{}, err
	}
	candidates := subjectScopes
	if requested != "" {
		candidates, err = Scopes(requested)
		if err != nil {
			return Result{}, err
		}
	}
	var scopes []string
	for _, scope := range candidates {
		if slices.Contains(subjectScopes, scope) && slices.Contains(actorScopes, scope) && slices.Contains(ceiling, scope) {
			scopes = append(scopes, scope)
		} else if requested != "" {
			return Result{}, ErrScope
		}
	}
	if len(scopes) == 0 {
		return Result{}, ErrScope
	}
	depth := 0
	for a := subject.Act; a != nil; a = a.Act {
		depth++
		if depth >= 8 || a.Subject == "" {
			return Result{}, ErrDenied
		}
	}
	expiry := time.Now().Add(time.Minute)
	for _, c := range []Claims{subject, actor} {
		if c.Expiry.Time().Before(expiry) {
			expiry = c.Expiry.Time()
		}
	}
	act := &Actor{Subject: actor.Subject, Issuer: actor.Issuer, Act: subject.Act}
	scope := strings.Join(scopes, " ")
	access, err := s.Issuer.Mint(tenant, subject.Subject, audience, scope, jkt, act, expiry)
	if err != nil {
		return Result{}, err
	}
	return Result{AccessToken: access, Scope: scope, ExpiresAt: expiry.Truncate(time.Second)}, nil
}

func Scopes(raw string) ([]string, error) {
	if raw == "" {
		return nil, ErrScope
	}
	seen := make(map[string]bool)
	var scopes []string
	for _, s := range strings.Split(raw, " ") {
		if s == "" {
			return nil, ErrScope
		}
		for _, r := range s {
			if r < 0x21 || r > 0x7e || r == '"' || r == '\\' || r == '*' {
				return nil, ErrScope
			}
		}
		if !seen[s] {
			scopes = append(scopes, s)
			seen[s] = true
		}
	}
	return scopes, nil
}
