# CODEX_SPEC: BastionAuth — Go OAuth 2.1, Token Exchange (RFC 8693), DPoP (RFC 9449) & Postgres RLS Guardrails

Build a genuine, production-structured Go systems repository (NO toy CRUD, NO hardcoded mocks pretending to pass).

## Required Architecture & Non-Trivial Invariants
1. **Go Module (`go.mod`, Go 1.22+):** Clean package layout: `cmd/bastionauth`, `internal/oauth`, `internal/dpop`, `internal/exchange`, `internal/store`, `internal/migrationlint`, `rfcs/001-token-exchange-and-rls.md`, `migrations/`.
2. **OAuth 2.1 + PKCE (`internal/oauth`):**
   - Strictly enforce `S256` PKCE (`plain` rejected with 400 `invalid_request`).
   - Exact `redirect_uri` verification, single-use authorization codes, state CSRF binding.
   - **Atomic Grant Revocation Invariant:** Revoking a client grant (`RevokeGrant(ctx, userID, clientID)`) executes atomically so **any pending/unexchanged authorization codes issued BEFORE revocation AND derived refresh tokens cannot be exchanged**, returning RFC 6749 §5.2 `invalid_grant` even under concurrent revoke vs `/oauth/token` exchange goroutines (`SELECT ... FOR UPDATE` / mutex+versioned DB store in tests & Postgres SQL). Re-consent after revoke issues a fresh grant whose new codes DO work.
3. **RFC 8693 On-Behalf-Of Token Exchange (`internal/exchange`):**
   - Verifies both `subject_token` and `actor_token` (Ed25519 / ES256 / RS256 JWKS with `kid` cache & key rotation support).
   - Computes strict **scope intersection** (`effective = requested ∩ subject ∩ actor ∩ policy_ceiling`). Any attempted scope escalation or unverified actor fails closed (`invalid_scope` / `access_denied`).
   - Preserves `act` claim chain and mints short-lived audience-bound (`aud`) downstream tokens.
4. **RFC 9449 DPoP Sender-Constrained Tokens (`internal/dpop`):**
   - Verifies DPoP proof JWT (`typ: dpop+jwt`), embedded JWK thumbprint (`jkt` SHA-256), `htm` & `htu` normalization, `ath` access-token hash binding, max `iat` skew (`<=60s`), and atomic `jti` single-use replay store with TTL eviction.
5. **Multi-Tenant PostgreSQL RLS & Migration Linter (`migrations/` + `internal/migrationlint`):**
   - SQL schemas with `FORCE ROW LEVEL SECURITY`, `(SELECT current_setting('app.tenant_id', true))` indexed composite keys, and transaction-pool-safe `WithTenantTx(ctx, tenantID, fn)` using `SET LOCAL` + reset.
   - `cmd/migrationlint`: AST/SQL static linter failing any DDL migration lacking `lock_timeout`, `statement_timeout`, or using blocking `CREATE INDEX` instead of `CREATE INDEX CONCURRENTLY`, or `NOT NULL` without `NOT VALID` + `VALIDATE CONSTRAINT`.
6. **Mandatory Tests (`go test -race ./...`):**
   - `TestConcurrentRevokeAndExchange`: 50 goroutines × 100 iterations racing revoke vs exchange; 0 post-revoke tokens issued.
   - `TestDPoPReplayAndBinding`: `jti` replay rejected 100%; method/URL mismatch rejected; `ath` mismatch rejected.
   - `TestRFC8693PrivilegeEscalationBlocked`: confused-deputy & wildcard scope escalation blocked; multi-hop `act` chain preserved.
   - `TestMigrationLinter`: catches unsafe locking DDL (`NOT NULL`, non-concurrent index) and passes safe expand-and-contract DDL.
   - Real Postgres integration test if `DATABASE_URL` env is set (configured in GitHub Actions `postgres:16` service container!), plus deterministic in-memory transactional store implementing the exact `Store` interface for offline `go test -race ./...`.
7. **Reproducible Benchmark (`benchmarks/run_bench.go` / `benchmarks/RESULTS.md`):**
   - Actually execute Go benchmarks + concurrent HTTP token-exchange / DPoP verification load test (`httptest` server) during build/CI and record the **EXACT observed req/s, p50/p95/p99 latency, allocations/op, and zero-race verification** in `benchmarks/RESULTS.md`. Never invent numbers!

## GitHub Actions CI & Clean-Up
- Update `.github/workflows/ci.yml` to run `go test -race -v ./...` against a real `postgres:16` service container, run `go run ./cmd/migrationlint ./migrations`, and run the benchmark sanity check.
- Update `README.md` with clear architecture diagram, RFC summary, threat model, explicit failure modes/non-goals, and exact benchmark commands.
- **CRITICAL:** Before committing/pushing final work, run `git rm CODEX_SPEC.md` so no spec file remains in the repo!
