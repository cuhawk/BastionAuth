package exchange_test

import (
	"context"
	"errors"
	"testing"

	"github.com/cuhawk/BastionAuth/internal/exchange"
	"github.com/cuhawk/BastionAuth/internal/joseutil"
	"github.com/cuhawk/BastionAuth/internal/testutil"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestRFC8693PrivilegeEscalationBlocked(t *testing.T) {
	keys := testutil.NewKeys()
	keysServer := keys.JWKS()
	defer keysServer.Close()
	signer := keys.Signer("at+jwt", false)
	verifier := exchange.Verifier{Keys: &exchange.JWKS{URL: keysServer.URL}, Issuer: "issuer", Audience: "exchange"}
	service := exchange.Service{Verifier: verifier, Issuer: exchange.Issuer{Name: "issuer", Signer: signer}, Targets: map[string][]string{"inventory": {"read", "write"}}}
	history := &exchange.Actor{Subject: "previous", Act: &exchange.Actor{Subject: "initial"}}
	subject := testutil.Access(signer, "issuer", "tenant", "user", "exchange", "read write admin", &exchange.Actor{Subject: "delegate", Issuer: "issuer"}, history)
	actor := testutil.Access(signer, "issuer", "tenant", "delegate", "exchange", "read admin", nil, nil)
	wrongActor := testutil.Access(signer, "issuer", "tenant", "different", "exchange", "read", nil, nil)
	forgery := testutil.Access(testutil.NewKeys().Signer("at+jwt", false), "issuer", "tenant", "delegate", "exchange", "read", nil, nil)
	wrongTenant := testutil.Access(signer, "issuer", "different", "delegate", "exchange", "read", nil, nil)
	wrongAudience := testutil.Access(signer, "issuer", "tenant", "delegate", "inventory", "read", nil, nil)
	for _, tc := range []struct {
		name, client, actor, target, scope string
		want                               error
	}{
		{"wildcard", "delegate", actor, "inventory", "*", exchange.ErrScope},
		{"actor ceiling", "delegate", actor, "inventory", "read write", exchange.ErrScope},
		{"policy ceiling", "delegate", actor, "inventory", "admin", exchange.ErrScope},
		{"unverified actor", "delegate", forgery, "inventory", "read", exchange.ErrDenied},
		{"confused deputy", "different", wrongActor, "inventory", "read", exchange.ErrDenied},
		{"caller impersonation", "different", actor, "inventory", "read", exchange.ErrDenied},
		{"unregistered audience", "delegate", actor, "unknown", "read", exchange.ErrDenied},
		{"wrong actor tenant", "delegate", wrongTenant, "inventory", "read", exchange.ErrDenied},
		{"wrong actor audience", "delegate", wrongAudience, "inventory", "read", exchange.ErrDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := service.Exchange(context.Background(), "tenant", tc.client, subject, tc.actor, tc.target, tc.scope, "thumbprint"); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("omitted scope uses intersection", func(t *testing.T) {
		result, err := service.Exchange(t.Context(), "tenant", "delegate", subject, actor, "inventory", "", "thumbprint")
		if err != nil || result.Scope != "read" {
			t.Fatalf("want read-only exchange, got %q, %v", result.Scope, err)
		}
	})
	t.Run("missing sender binding", func(t *testing.T) {
		if _, err := service.Exchange(t.Context(), "tenant", "delegate", subject, actor, "inventory", "read", ""); !errors.Is(err, exchange.ErrDenied) {
			t.Fatalf("unbound exchange: %v", err)
		}
	})
	result, err := service.Exchange(context.Background(), "tenant", "delegate", subject, actor, "inventory", "read", "thumbprint")
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.ParseSigned(result.AccessToken, joseutil.Algorithms)
	if err != nil {
		t.Fatal(err)
	}
	var c exchange.Claims
	if err := token.Claims(keys.Public, &c); err != nil {
		t.Fatal(err)
	}
	if c.Subject != "user" || !c.Audience.Contains("inventory") || c.Scope != "read" || c.CNF == nil || c.CNF.JKT != "thumbprint" || c.Act == nil || c.Act.Subject != "delegate" || c.Act.Act == nil || c.Act.Act.Subject != "previous" || c.Act.Act.Act == nil || c.Act.Act.Act.Subject != "initial" {
		t.Fatalf("unexpected exchange claims: %+v", c)
	}
}
