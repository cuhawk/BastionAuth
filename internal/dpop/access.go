package dpop

import (
	"context"

	"github.com/cuhawk/BastionAuth/internal/exchange"
)

// VerifyAccess authenticates a DPoP-bound token at a resource server.
// target is the externally visible request URI from a trusted configuration.
func (v Verifier) VerifyAccess(ctx context.Context, tokens exchange.Verifier, tenant, accessToken, proof, method, target string) (exchange.Claims, error) {
	c, err := tokens.Verify(ctx, accessToken, tenant)
	if err != nil || c.CNF == nil || c.CNF.JKT == "" {
		return exchange.Claims{}, ErrProof
	}
	if revoked, err := v.Store.AccessRevoked(ctx, tenant, c.ID); err != nil || revoked {
		return exchange.Claims{}, ErrProof
	}
	if _, err := v.Verify(ctx, tenant, proof, method, target, accessToken, c.CNF.JKT); err != nil {
		return exchange.Claims{}, err
	}
	return c, nil
}
