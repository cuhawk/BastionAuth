package store_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cuhawk/BastionAuth/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	pg "github.com/pganalyze/pg_query_go/v6"
)

func TestPostgresRLSAndRevocation(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	namespace := "bastion_" + strings.ToLower(strings.ReplaceAll(store.Secret()[:16], "-", "a"))
	role := namespace + "_app"
	exec := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec("CREATE SCHEMA " + namespace)
	defer admin.Exec(context.Background(), "DROP SCHEMA "+namespace+" CASCADE")
	exec("CREATE ROLE " + role + " NOLOGIN NOSUPERUSER NOBYPASSRLS")
	defer func() {
		if _, err := admin.Exec(context.Background(), "DROP OWNED BY "+role); err != nil {
			t.Error(err)
		}
		if _, err := admin.Exec(context.Background(), "DROP ROLE "+role); err != nil {
			t.Error(err)
		}
	}()
	exec("SET search_path TO " + namespace)
	files, err := filepath.Glob("../../migrations/*.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("migration paths: %v, %v", files, err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		sql := string(data)
		statements, err := pg.SplitWithParser(sql, true)
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range statements {
			exec(stmt)
		}
	}
	exec("GRANT USAGE ON SCHEMA " + namespace + " TO " + role)
	exec("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA " + namespace + " TO " + role)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 8
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		if _, err := c.Exec(ctx, "SET ROLE "+role); err != nil {
			return err
		}
		_, err := c.Exec(ctx, "SET search_path TO "+namespace)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	p := store.Postgres{Pool: pool}
	c := store.Credential{User: "user", Client: "client", Expires: time.Now().Add(time.Hour)}
	if err := p.Consent(ctx, "alpha", "old", c); err != nil {
		t.Fatal(err)
	}
	if err := p.Consent(ctx, "beta", "old", c); err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("force rollback")
	if err := p.WithTenantTx(ctx, "alpha", func(tx pgx.Tx) error {
		var tenant string
		if err := tx.QueryRow(ctx, "SELECT tenant_id FROM grants").Scan(&tenant); err != nil {
			return err
		}
		if tenant != "alpha" {
			return errors.New("RLS exposed another tenant")
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	// The transaction-local tenant identifier must round-trip as a literal.
	const quotedTenant = "tenant'quoted"
	if err := p.Consent(ctx, quotedTenant, "quoted-code", c); err != nil {
		t.Fatal(err)
	}
	if err := p.WithTenantTx(ctx, quotedTenant, func(tx pgx.Tx) error {
		var tenant string
		if err := tx.QueryRow(ctx, "SELECT tenant_id FROM grants").Scan(&tenant); err != nil {
			return err
		}
		if tenant != quotedTenant {
			return errors.New("quoted tenant did not round-trip")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var visible int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM grants").Scan(&visible); err != nil || visible != 0 {
		t.Fatalf("tenant leaked after rollback: %d %v", visible, err)
	}
	err = p.WithTenantTx(ctx, "alpha", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO grants(tenant_id,user_id,client_id) VALUES ('beta','intruder','client')")
		return err
	})
	if err == nil {
		t.Fatal("RLS accepted cross-tenant insert")
	}
	var forced int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM pg_class WHERE relnamespace=$1::regnamespace AND relrowsecurity AND relforcerowsecurity", namespace).Scan(&forced); err != nil || forced != 3 {
		t.Fatalf("forced RLS tables: %d %v", forced, err)
	}

	for range 30 {
		old, pending, refresh := store.Secret(), store.Secret(), store.Secret()
		if err := p.Consent(ctx, "alpha", old, c); err != nil {
			t.Fatal(err)
		}
		if err := p.Consent(ctx, "alpha", pending, c); err != nil {
			t.Fatal(err)
		}
		issue := func(c store.Credential) (store.Credential, error) { return c, nil }
		result := make(chan error, 1)
		go func() { result <- p.Rotate(ctx, "alpha", old, refresh, issue) }()
		revokeErr := p.Revoke(ctx, "alpha", c.User, c.Client)
		rotateErr := <-result
		if revokeErr != nil {
			t.Fatal(revokeErr)
		}
		if rotateErr != nil && !errors.Is(rotateErr, store.ErrInvalid) {
			t.Fatal(rotateErr)
		}
		fresh := store.Secret()
		if err := p.Consent(ctx, "alpha", fresh, c); err != nil {
			t.Fatal(err)
		}
		for _, stale := range []string{old, pending, refresh} {
			if err := p.Rotate(ctx, "alpha", stale, store.Secret(), issue); !errors.Is(err, store.ErrInvalid) {
				t.Fatalf("pre-revoke credential after re-consent: %v", err)
			}
		}
		if err := p.Rotate(ctx, "alpha", fresh, store.Secret(), issue); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Rotate(ctx, "beta", "old", "fresh", func(c store.Credential) (store.Credential, error) { return c, nil }); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM credentials").Scan(&visible); err != nil || visible != 0 {
		t.Fatalf("tenant leaked after commit: %d %v", visible, err)
	}
	now := time.Now()
	var claimed atomic.Int32
	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			ok, err := p.ClaimProof(ctx, "alpha", "jkt", "jti", now, now.Add(time.Minute))
			if err != nil {
				t.Error(err)
			}
			if ok {
				claimed.Add(1)
			}
		})
	}
	wg.Wait()
	if got := claimed.Load(); got != 1 {
		t.Fatalf("accepted %d concurrent proofs", got)
	}
	claimed.Store(0)
	for range 24 {
		wg.Go(func() {
			ok, err := p.ClaimProof(ctx, "alpha", "jkt", "jti", now.Add(time.Minute), now.Add(2*time.Minute))
			if err != nil {
				t.Error(err)
			}
			if ok {
				claimed.Add(1)
			}
		})
	}
	wg.Wait()
	if got := claimed.Load(); got != 1 {
		t.Fatalf("accepted %d concurrent proofs after expiry", got)
	}
}
