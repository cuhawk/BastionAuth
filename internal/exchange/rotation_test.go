package exchange_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cuhawk/BastionAuth/internal/exchange"
	"github.com/cuhawk/BastionAuth/internal/testutil"
	"github.com/go-jose/go-jose/v4"
)

func TestJWKSSigningAlgorithmsAndRotation(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ed := testutil.NewKeys()
	var published atomic.Pointer[jose.JSONWebKeySet]
	published.Store(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &ec.PublicKey, KeyID: "ec", Algorithm: "ES256"},
		{Key: &rsaKey.PublicKey, KeyID: "rsa", Algorithm: "RS256"},
	}})
	var requests atomic.Int32
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_ = json.NewEncoder(w).Encode(published.Load())
	}))
	defer endpoint.Close()
	const issuer, tenant, audience = "https://issuer.example", "tenant", "exchange"
	verifier := exchange.Verifier{Issuer: issuer, Audience: audience, Keys: &exchange.JWKS{URL: endpoint.URL, Client: endpoint.Client()}}
	token := func(alg jose.SignatureAlgorithm, kid string, key any) string {
		t.Helper()
		options := (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", kid)
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, options)
		if err != nil {
			t.Fatal(err)
		}
		return testutil.Access(signer, issuer, tenant, "user", audience, "read", nil, nil)
	}
	original := token(jose.ES256, "ec", ec)
	for _, value := range []string{original, token(jose.RS256, "rsa", rsaKey)} {
		if _, err := verifier.Verify(t.Context(), value, tenant); err != nil {
			t.Fatal(err)
		}
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("cached keys used %d JWKS fetches", got)
	}
	published.Store(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: ed.Public, KeyID: "ed", Algorithm: "EdDSA"},
	}})
	time.Sleep(time.Second)
	if _, err := verifier.Verify(t.Context(), token(jose.EdDSA, "ed", ed.Private), tenant); err != nil {
		t.Fatalf("rotation to a new kid: %v", err)
	}
	if _, err := verifier.Verify(t.Context(), original, tenant); !errors.Is(err, exchange.ErrDenied) {
		t.Fatalf("retired kid returned %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("rotation used %d JWKS fetches", got)
	}
}
