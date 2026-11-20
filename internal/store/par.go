package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type PushedRequest struct {
	Client  string
	Form    string
	Expires time.Time
}

func (m *Memory) SavePushedRequest(ctx context.Context, tenant, digest string, request PushedRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	now := time.Now()
	if !now.Before(m.nextPARSweep) {
		for key, pending := range m.pushed {
			if !now.Before(pending.Expires) {
				delete(m.pushed, key)
			}
		}
		m.nextPARSweep = now.Add(time.Minute)
	}
	m.pushed[credentialKey{tenant, digest}] = request
	return nil
}

func (m *Memory) TakePushedRequest(ctx context.Context, tenant, client, digest string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	key := credentialKey{tenant, digest}
	request, ok := m.pushed[key]
	if !ok || request.Client != client || !time.Now().Before(request.Expires) {
		return "", ErrInvalid
	}
	delete(m.pushed, key)
	return request.Form, nil
}

func (p Postgres) SavePushedRequest(ctx context.Context, tenant, digest string, request PushedRequest) error {
	return p.WithTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM pushed_requests AS pending USING (
   SELECT digest FROM pushed_requests WHERE tenant_id=$1 AND expires_at <= clock_timestamp()
   ORDER BY expires_at LIMIT 128 FOR UPDATE SKIP LOCKED
  ) AS expired WHERE pending.tenant_id=$1 AND pending.digest=expired.digest`, tenant); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO pushed_requests(tenant_id,digest,client_id,expires_at,form) VALUES($1,$2,$3,$4,$5)`,
			tenant, digest, request.Client, request.Expires, request.Form)
		return err
	})
}

func (p Postgres) TakePushedRequest(ctx context.Context, tenant, client, digest string) (form string, err error) {
	err = p.WithTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `DELETE FROM pushed_requests WHERE tenant_id=$1 AND digest=$2 AND client_id=$3
   AND expires_at > clock_timestamp() RETURNING form`, tenant, digest, client).Scan(&form)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalid
		}
		return err
	})
	return form, err
}
