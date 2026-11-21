package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

func saveAccess(ctx context.Context, tx pgx.Tx, tenant string, token AccessToken, generation int64) error {
	_, err := tx.Exec(ctx, `INSERT INTO access_tokens
		(tenant_id,digest,jti,user_id,client_id,generation,audience,scope,jkt,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		tenant, token.Digest, token.JTI, token.User, token.Client, generation, token.Audience, token.Scope, token.JKT, token.Expires)
	return err
}

func (p Postgres) SaveAccess(ctx context.Context, tenant string, token AccessToken) error {
	return p.WithTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var generation int64
		var active bool
		err := tx.QueryRow(ctx, `INSERT INTO grants(tenant_id,user_id,client_id) VALUES($1,$2,$3)
			ON CONFLICT(tenant_id,user_id,client_id) DO UPDATE SET active=grants.active
			RETURNING generation,active`, tenant, token.User, token.Client).Scan(&generation, &active)
		if err != nil {
			return err
		}
		if !active {
			return ErrInvalid
		}
		return saveAccess(ctx, tx, tenant, token, generation)
	})
}

func (p Postgres) LookupAccess(ctx context.Context, tenant, digest string) (token AccessToken, err error) {
	err = p.WithTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT jti,user_id,client_id,audience,scope,jkt,expires_at
			FROM access_tokens WHERE tenant_id=$1 AND digest=$2 AND NOT revoked AND expires_at>now()`,
			tenant, digest).Scan(&token.JTI, &token.User, &token.Client, &token.Audience, &token.Scope, &token.JKT, &token.Expires)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrInvalid
	}
	token.Digest = digest
	return token, err
}

func (p Postgres) AccessRevoked(ctx context.Context, tenant, jti string) (revoked bool, err error) {
	err = p.WithTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM access_tokens
			WHERE tenant_id=$1 AND jti=$2 AND revoked AND expires_at>now())`, tenant, jti).Scan(&revoked)
	})
	return revoked, err
}

func revokeGrant(ctx context.Context, tx pgx.Tx, tenant, user, client string, generation *int64) error {
	var revokedGeneration int64
	err := tx.QueryRow(ctx, `UPDATE grants SET active=false,generation=generation+1
		WHERE tenant_id=$1 AND user_id=$2 AND client_id=$3 AND active AND ($4::bigint IS NULL OR generation=$4)
		RETURNING generation-1`, tenant, user, client, generation).Scan(&revokedGeneration)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE access_tokens SET revoked=true
		WHERE tenant_id=$1 AND user_id=$2 AND client_id=$3 AND generation=$4 AND expires_at>now()`,
		tenant, user, client, revokedGeneration)
	return err
}

func (p Postgres) RevokeToken(ctx context.Context, tenant, client, digest string) error {
	return p.WithTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var user string
		var generation int64
		err := tx.QueryRow(ctx, `SELECT user_id,generation FROM access_tokens
			WHERE tenant_id=$1 AND digest=$2 AND client_id=$3 AND expires_at>now()
			UNION ALL
			SELECT user_id,generation FROM credentials
			WHERE tenant_id=$1 AND digest=$2 AND client_id=$3 AND expires_at>now()
			AND payload->>'Kind' IN ('refresh_token','spent_refresh_token')`, tenant, digest, client).Scan(&user, &generation)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return revokeGrant(ctx, tx, tenant, user, client, &generation)
	})
}
