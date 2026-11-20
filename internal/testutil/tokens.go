// Package testutil provides signed fixtures for protocol tests and benchmarks.
package testutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/cuhawk/BastionAuth/internal/exchange"
	"github.com/cuhawk/BastionAuth/internal/store"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type Keys struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

func NewKeys() Keys {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return Keys{pub, priv}
}
func (k Keys) Signer(typ string, proof bool) jose.Signer {
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	if proof {
		opts.WithHeader(jose.HeaderKey("jwk"), jose.JSONWebKey{Key: k.Public})
	} else {
		opts.WithHeader(jose.HeaderKey("kid"), "test-key")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: k.Private}, opts)
	if err != nil {
		panic(err)
	}
	return signer
}
func (k Keys) JWKS() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: k.Public, KeyID: "test-key", Algorithm: "EdDSA", Use: "sig"}}})
	}))
}
func Signed(s jose.Signer, claims any) string {
	raw, err := jwt.Signed(s).Claims(claims).Serialize()
	if err != nil {
		panic(err)
	}
	return raw
}
func Access(s jose.Signer, issuer, tenant, subject, audience, scope string, mayAct, act *exchange.Actor) string {
	return Signed(s, exchange.Claims{Claims: jwt.Claims{Issuer: issuer, Subject: subject, Audience: jwt.Audience{audience}, Expiry: jwt.NewNumericDate(time.Now().Add(5 * time.Minute))}, Tenant: tenant, Scope: scope, MayAct: mayAct, Act: act})
}
func Proof(s jose.Signer, method, target, access, jti string, now time.Time) string {
	claims := map[string]any{"htm": method, "htu": target, "iat": now.Unix(), "jti": jti}
	if access != "" {
		claims["ath"] = store.Digest(access)
	}
	return Signed(s, claims)
}
