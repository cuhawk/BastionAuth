package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Postgres struct{ Pool *pgxpool.Pool }

func (p Postgres) WithTenantTx(ctx context.Context, tenant string, fn func(pgx.Tx) error) error {
	if tenant == "" || strings.IndexByte(tenant, 0) >= 0 {
		return errors.New("invalid tenant")
	}
	tx, err := p.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	// PostgreSQL SET requires a literal. Simple protocol safely quotes the argument.
	if _, err = tx.Exec(ctx, "SET LOCAL app.tenant_id = $1", pgx.QueryExecModeSimpleProtocol, tenant); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	// PostgreSQL resets transaction-local settings on commit or rollback.
	return tx.Commit(ctx)
}

func save(ctx context.Context, tx pgx.Tx, tenant, digest string, generation int64, c Credential) error {
	payload, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO credentials(tenant_id,digest,user_id,client_id,generation,expires_at,payload) VALUES ($1,$2,$3,$4,$5,$6,$7)`, tenant, digest, c.User, c.Client, generation, c.Expires, string(payload))
	return err
}

func (p Postgres) Consent(ctx context.Context, tenant, digest string, c Credential) error {
	return p.WithTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var generation int64
		err := tx.QueryRow(ctx, `INSERT INTO grants(tenant_id,user_id,client_id) VALUES($1,$2,$3)
  ON CONFLICT(tenant_id,user_id,client_id) DO UPDATE SET active=true RETURNING generation`, tenant, c.User, c.Client).Scan(&generation)
		if err != nil {
			return err
		}
		return save(ctx, tx, tenant, digest, generation, c)
	})
}

func (p Postgres) Revoke(ctx context.Context, tenant, user, client string) error {
	return p.WithTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE grants SET active=false,generation=generation+1 WHERE tenant_id=$1 AND user_id=$2 AND client_id=$3`, tenant, user, client)
		return err
	})
}

func (p Postgres) Rotate(ctx context.Context, tenant, oldDigest, newDigest string, issue func(Credential) (Credential, error)) error {
	return p.WithTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var user, client string
		err := tx.QueryRow(ctx, `SELECT user_id,client_id FROM credentials WHERE tenant_id=$1 AND digest=$2`, tenant, oldDigest).Scan(&user, &client)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalid
		}
		if err != nil {
			return err
		}
		var generation int64
		var active bool
		err = tx.QueryRow(ctx, `SELECT generation,active FROM grants WHERE tenant_id=$1 AND user_id=$2 AND client_id=$3 FOR UPDATE`, tenant, user, client).Scan(&generation, &active)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalid
		}
		if err != nil {
			return err
		}
		if !active {
			return ErrInvalid
		}
		var payload []byte
		err = tx.QueryRow(ctx, `DELETE FROM credentials WHERE tenant_id=$1 AND digest=$2 AND generation=$3 RETURNING payload`, tenant, oldDigest, generation).Scan(&payload)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalid
		}
		if err != nil {
			return err
		}
		var old Credential
		if err = json.Unmarshal(payload, &old); err != nil {
			return err
		}
		next, err := issue(old)
		if err != nil {
			return err
		}
		return save(ctx, tx, tenant, newDigest, generation, next)
	})
}

func (p Postgres) ClaimProof(ctx context.Context, tenant, key, jti string, now, expires time.Time) (claimed bool, err error) {
	err = p.WithTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		// Limit cleanup work and skip rows that concurrent claims already locked.
		if _, err := tx.Exec(ctx, `DELETE FROM dpop_replays AS replay USING (
			SELECT thumbprint, jti FROM dpop_replays
			WHERE tenant_id=$1 AND expires_at <= $2
			  AND (thumbprint, jti) <> ($3, $4)
			ORDER BY expires_at LIMIT 128 FOR UPDATE SKIP LOCKED
		) AS expired
		WHERE replay.tenant_id=$1 AND replay.thumbprint=expired.thumbprint AND replay.jti=expired.jti`,
			tenant, now, key, jti); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO dpop_replays(tenant_id,thumbprint,jti,expires_at) VALUES($1,$2,$3,$4)
			ON CONFLICT (tenant_id,thumbprint,jti) DO UPDATE SET expires_at=EXCLUDED.expires_at
			WHERE dpop_replays.expires_at <= $5`, tenant, key, jti, expires, now)
		claimed = tag.RowsAffected() == 1
		return err
	})
	return claimed, err
}
