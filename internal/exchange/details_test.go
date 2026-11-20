package exchange_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cuhawk/BastionAuth/internal/exchange"
	"github.com/cuhawk/BastionAuth/internal/testutil"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestAuthorizationDetailsValidation(t *testing.T) {
	for name, input := range map[string]string{
		"missing": "", "null": "null", "object": `{"type":"inventory"}`, "empty": "[]",
		"non-object element": `[null]`, "missing type": `[{}]`, "invalid type": `[{"type":1}]`,
		"empty type": `[{"type":" "}]`, "actions string": `[{"type":"inventory","actions":"read"}]`,
		"empty actions":      `[{"type":"inventory","actions":[]}]`,
		"invalid action":     `[{"type":"inventory","actions":[true]}]`,
		"invalid location":   `[{"type":"inventory","locations":[null]}]`,
		"invalid identifier": `[{"type":"inventory","identifier":42}]`,
		"duplicate type":     `[{"type":"a","type":"b"}]`, "duplicate nested key": `[{"type":"a","filter":{"n":1,"n":2}}]`,
		"trailing JSON": `[{"type":"a"}] []`, "oversize": "[{\"type\":\"" + strings.Repeat("a", 8192) + "\"}]",
		"nested too deeply": `[{"type":"a","filter":` + strings.Repeat("[", 18) + "1" + strings.Repeat("]", 18) + "}]",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := exchange.ParseDetails(input); !errors.Is(err, exchange.ErrDetails) {
				t.Fatalf("expected invalid_authorization_details, got %v", err)
			}
		})
	}
}

func TestRFC8693AuthorizationDetailsNarrowing(t *testing.T) {
	keys := testutil.NewKeys()
	jwks := keys.JWKS()
	defer jwks.Close()
	signer := keys.Signer("at+jwt", false)
	verifier := exchange.Verifier{Keys: &exchange.JWKS{URL: jwks.URL}, Issuer: "issuer", Audience: "exchange"}
	service := exchange.Service{Verifier: verifier, Issuer: exchange.Issuer{Name: "issuer", Signer: signer}, Targets: map[string][]string{"inventory": {"read", "write"}}}
	const broad = `[{"type":"inventory","actions":["read","write"],"locations":["https://inventory/a","https://inventory/b"],"identifier":"tenant-1","filter":{"revision":9007199254740993,"archived":false}}]`
	const narrow = `[{"type":"inventory","actions":["read"],"locations":["https://inventory/a"],"identifier":"tenant-1","filter":{"archived":false,"revision":9007199254740993}}]`
	parse := func(raw string) exchange.Details {
		t.Helper()
		if raw == "" {
			return nil
		}
		details, err := exchange.ParseDetails(raw)
		if err != nil {
			t.Fatal(err)
		}
		return details
	}
	mint := func(subject, scope, details string, mayAct *exchange.Actor) string {
		t.Helper()
		claims := exchange.Claims{
			Claims: jwt.Claims{Issuer: "issuer", Subject: subject, Audience: jwt.Audience{"exchange"}, Expiry: jwt.NewNumericDate(time.Now().Add(time.Minute))},
			Tenant: "tenant", Scope: scope, MayAct: mayAct, AuthorizationDetails: parse(details),
		}
		raw, err := jwt.Signed(signer).Claims(claims).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	subject := mint("user", "read write", broad, &exchange.Actor{Subject: "delegate"})
	actor := mint("delegate", "read", narrow, nil)
	unqualifiedActor := mint("delegate", "read", "", nil)
	limitedSubject := mint("user", "read write", narrow, &exchange.Actor{Subject: "delegate"})
	for _, tc := range []struct {
		name, subject, actor, scope, request string
		want                                 error
	}{
		{"narrow", subject, actor, "read", narrow, nil},
		{"inherit", limitedSubject, actor, "", "", nil},
		{"inherit with unconstrained actor", subject, unqualifiedActor, "read", "", nil},
		{"cannot inherit over actor limit", subject, actor, "read", "", exchange.ErrDetails},
		{"scope ceiling", subject, actor, "write", narrow, exchange.ErrScope},
		{"actor detail ceiling", subject, actor, "read", broad, exchange.ErrDetails},
		{"subject detail ceiling", limitedSubject, unqualifiedActor, "read", broad, exchange.ErrDetails},
		{"different location", subject, actor, "read", strings.Replace(narrow, "/a", "/c", 1), exchange.ErrDetails},
		{"removed location", subject, actor, "read", strings.Replace(narrow, `"locations":["https://inventory/a"],`, "", 1), exchange.ErrDetails},
		{"different identifier", subject, actor, "read", strings.Replace(narrow, "tenant-1", "tenant-2", 1), exchange.ErrDetails},
		{"different resource type", subject, actor, "read", strings.Replace(narrow, `"type":"inventory"`, `"type":"files"`, 1), exchange.ErrDetails},
		{"removed filter", subject, actor, "read", strings.Replace(narrow, `,"filter":{"archived":false,"revision":9007199254740993}`, "", 1), exchange.ErrDetails},
		{"changed large integer", subject, actor, "read", strings.Replace(narrow, "9007199254740993", "9007199254740992", 1), exchange.ErrDetails},
		{"introduced details", mint("user", "read", "", &exchange.Actor{Subject: "delegate"}), actor, "read", narrow, exchange.ErrDetails},
		{"rich-only grant", mint("user", "", broad, &exchange.Actor{Subject: "delegate"}), mint("delegate", "", narrow, nil), "", narrow, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := service.ExchangeWithDetails(t.Context(), "tenant", "delegate", tc.subject, tc.actor, "inventory", tc.scope, "jkt", parse(tc.request))
			if !errors.Is(err, tc.want) {
				t.Fatalf("exchange: got %v, want %v", err, tc.want)
			}
			if err != nil {
				return
			}
			expected := tc.request
			if expected == "" {
				expected = narrow
				if tc.subject == subject {
					expected = broad
				}
			}
			target := verifier
			target.Audience = "inventory"
			claims, err := target.Verify(t.Context(), result.AccessToken, "tenant")
			if err != nil || !reflect.DeepEqual(claims.AuthorizationDetails, parse(expected)) || !reflect.DeepEqual(claims.AuthorizationDetails, result.AuthorizationDetails) {
				t.Fatalf("authorization details in token: %+v %v", claims.AuthorizationDetails, err)
			}
		})
	}
}
