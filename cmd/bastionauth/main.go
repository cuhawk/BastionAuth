package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cuhawk/BastionAuth/internal/dpop"
	"github.com/cuhawk/BastionAuth/internal/exchange"
	"github.com/cuhawk/BastionAuth/internal/oauth"
	"github.com/cuhawk/BastionAuth/internal/store"
	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type trust struct{ Issuer, Audience, JWKSURL string }
type config struct {
	Tenant, Origin, Audience, Issuer, KeyID, SigningKeyFile, Listen string
	Clients                                                         map[string]oauth.Client
	Targets                                                         map[string][]string
	Sessions, Exchange                                              trust
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return errors.New("usage: bastionauth CONFIG.json")
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		return err
	}
	defer f.Close()
	var cfg config
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&cfg); err != nil {
		return err
	}
	if err = cfg.validate(); err != nil {
		return err
	}
	data, err := os.ReadFile(cfg.SigningKeyFile)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return errors.New("expected PKCS#8 PEM signing key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return errors.New("expected Ed25519 signing key")
	}
	jwk := jose.JSONWebKey{Key: key.Public(), KeyID: cfg.KeyID, Algorithm: string(jose.EdDSA), Use: "sig"}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader(jose.HeaderKey("kid"), cfg.KeyID))
	if err != nil {
		return err
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL is required")
	}
	dbConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return errors.New("invalid DATABASE_URL")
	}
	dbConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	dbConfig.ConnConfig.StatementCacheCapacity = 0
	dbConfig.ConnConfig.DescriptionCacheCapacity = 0
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	startup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(startup, dbConfig)
	if err != nil {
		return err
	}
	defer pool.Close()
	var safe bool
	err = pool.QueryRow(startup, `SELECT NOT (rolsuper OR rolbypassrls) FROM pg_roles WHERE rolname=current_user`).Scan(&safe)
	if err != nil {
		return err
	}
	if !safe {
		return errors.New("database role must enforce row-level security")
	}
	db := store.Postgres{Pool: pool}
	s := oauth.Server{Tenant: cfg.Tenant, Origin: cfg.Origin, Audience: cfg.Audience, Clients: cfg.Clients, Store: db, Sessions: cfg.Sessions.verifier(), DPoP: dpop.Verifier{Store: db}, Exchange: exchange.Service{Verifier: cfg.Exchange.verifier(), Issuer: exchange.Issuer{Name: cfg.Issuer, Signer: signer}, Targets: cfg.Targets}}
	mux := http.NewServeMux()
	mux.Handle("/", s.Handler())
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})
	server := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 * 1024}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}

func (t trust) verifier() exchange.Verifier {
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return exchange.Verifier{Issuer: t.Issuer, Audience: t.Audience, Keys: &exchange.JWKS{URL: t.JWKSURL, Client: client}}
}

func httpsURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	return u, err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && !strings.Contains(raw, "#")
}

func (c config) validate() error {
	origin, ok := httpsURL(c.Origin)
	if !ok || origin.Path != "" || origin.RawQuery != "" || origin.ForceQuery || c.Tenant == "" || c.Audience == "" || c.Issuer == "" || c.KeyID == "" || c.SigningKeyFile == "" || c.Listen == "" || len(c.Clients) == 0 {
		return errors.New("missing or invalid server configuration")
	}
	for _, t := range []trust{c.Sessions, c.Exchange} {
		if _, ok := httpsURL(t.JWKSURL); !ok || t.Issuer == "" || t.Audience == "" {
			return errors.New("invalid trust configuration")
		}
	}
	if c.Sessions.Issuer == c.Exchange.Issuer && c.Sessions.Audience == c.Exchange.Audience {
		return errors.New("session and exchange trust must use separate token audiences or issuers")
	}
	for name, client := range c.Clients {
		if name == "" {
			return errors.New("empty client ID")
		}
		for _, redirect := range client.Redirects {
			u, ok := httpsURL(redirect)
			if !ok || u.Query().Has("code") || u.Query().Has("error") || u.Query().Has("state") {
				return fmt.Errorf("invalid redirect for client %q", name)
			}
		}
	}
	return nil
}
