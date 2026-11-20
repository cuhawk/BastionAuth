# BastionAuth

BastionAuth is a Go authorization service with S256 PKCE, MCP Client ID Metadata Documents, pushed authorization requests, rich authorization requests, delegated token exchange, and DPoP sender-constrained access tokens. Each deployment selects a tenant from server configuration. PostgreSQL policies enforce that tenant on every application transaction.

```mermaid
flowchart LR
    Browser -->|consent and revocation| Auth[BastionAuth]
    Client -->|code or refresh token and DPoP| Auth
    Delegate -->|subject token, actor token and DPoP| Auth
    Auth -->|verify issuer keys by kid| JWKS[Trusted JWKS endpoints]
    Auth -->|tenant-scoped transactions| DB[(PostgreSQL 16)]
    Auth -->|audience-bound DPoP token| Client
    Auth -->|delegated DPoP token| Delegate
    Client -->|token and fresh proof with ath| Resource[Resource server]
    Delegate -->|token and fresh proof with ath| Resource
```

## Protocols

| Endpoint | Input and behavior |
| --- | --- |
| `GET /oauth/authorize` | Renders consent for an authenticated session. Accepts a PAR reference or a direct request with `response_type=code`, an exact `redirect_uri`, `state`, S256 PKCE, and `scope`, `authorization_details`, or both. Accepts optional `dpop_jkt` for code binding. |
| `POST /oauth/authorize` | Processes the rendered consent form. Checks the HTTPS origin and session-bound form integrity, then redirects with the original `state` and a single-use code or denial. Clients verify `state` against their initiating session. |
| `POST /oauth/par` | Validates a form-encoded authorization request and returns HTTP 201 with a single-use `request_uri` and `expires_in`. |
| `POST /oauth/token` | Accepts form-encoded authorization-code, rotating refresh-token, and RFC 8693 requests with a fresh `DPoP` header. Public clients send `client_id`. Confidential clients use `client_secret_basic`. |
| `POST /oauth/grant/revoke` | Accepts form-encoded `client_id` from the user’s session and same origin. Revokes all codes and refresh tokens for that client grant. |
| `GET /.well-known/oauth-authorization-server` | Advertises the authorization, token, PAR, and JWKS endpoints and whether CIMD is enabled. |
| `GET /.well-known/jwks.json` | Serves the active public Ed25519 signing key. |

RFC 8693 requests use `urn:ietf:params:oauth:grant-type:token-exchange`, two access-token type identifiers (`urn:ietf:params:oauth:token-type:access_token`), and a configured `audience`. The client authenticates with its secret and presents an actor token naming that same client. The subject token must authorize that actor via `may_act`. Each requested scope must appear on both tokens and in the target policy. Unrecognized target, actor, or delegation fails with `access_denied`. Scope escalation fails with `invalid_scope`. An omitted `scope` defaults to the intersection of the subject scopes, actor scopes, and target policy. See the design RFC for the database and verification invariants. [RFC 001](rfcs/001-token-exchange-and-rls.md)

### MCP client metadata

Set `CIMDScopes` to enable HTTPS metadata-document URLs as public client IDs and list the scopes those clients may request. Omit the setting to disable URL resolution. The document must declare the exact URL as its `client_id` and an exact redirect URI for the authorization request. Supported callbacks use HTTPS or HTTP on an IP literal in the loopback range. The server displays the client name and metadata URL during consent, and the full URL identifies the stored grant. The metadata fetch uses public IPs, verified HTTPS, a 64 KiB body limit, and a bounded cache with ETag revalidation and a TTL of up to five minutes.

### Pushed and rich authorization requests

Submit the authorization parameters to `POST /oauth/par` using the same public identification or confidential client authentication as the token endpoint. Pass only `client_id` and the returned `request_uri` to `GET /oauth/authorize`. The reference expires after 60 seconds and is consumed atomically when an authenticated user opens it. The consent form and token redemption use the original request’s PKCE challenge.

`authorization_details` is a JSON array of objects with a `type` and any common or type-specific constraints. For example, `[{"type":"inventory","identifier":"warehouse-1","actions":["read"]}]` requests read access to one inventory. BastionAuth shows the approved details at consent and carries them into access tokens and refresh rotations. Resource servers enforce the details alongside the audience and scope.

During token exchange, an omitted `authorization_details` inherits the subject token’s details if permitted by the actor token. Each requested object must fit within one complete subject grant and, when the actor token has details, one complete actor grant. An exchange can drop entire objects or narrow the `actions`, `locations`, `datatypes`, and `privileges` lists. It must retain the object’s type, identifier, and type-specific values. Widening fails with `invalid_authorization_details`.

## Run

Use Go 1.25+, a C compiler for the PostgreSQL parser and race detector, and PostgreSQL 16. Apply migrations as a schema owner with `psql` in autocommit mode. The timeout settings and DDL in each file must run on the same connection. For a dedicated database:

```sh
psql "$MIGRATION_DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f migrations/001_core.sql -f migrations/002_expiration_indexes.sql \
  -f migrations/003_pushed_requests.sql
openssl genpkey -algorithm ED25519 -out signing-key.pem
go run ./cmd/bastionauth config.json
```

Give the service’s `DATABASE_URL` role schema usage and table CRUD privileges. Use a separate, non-owner role with `NOSUPERUSER NOBYPASSRLS` and restrict its connection to the service. For a transaction-mode PgBouncer connection, use the service’s default pgx execution mode, which avoids named prepared statements. Set `Issuer` to the external HTTPS authorization origin for metadata discovery. Terminate HTTPS at a trusted proxy and restrict access to the service listener. Configure ingress rate limits and keep service clocks synchronized.

Example `config.json`:

```json
{
  "Tenant": "north",
  "Origin": "https://auth.example.com",
  "Audience": "https://api.example.com",
  "Issuer": "https://auth.example.com",
  "KeyID": "signing-2026-01",
  "SigningKeyFile": "signing-key.pem",
  "Listen": "127.0.0.1:8080",
  "Clients": {
    "web": {
      "Redirects": ["https://web.example.com/callback"],
      "Scopes": ["inventory:read"]
    },
    "delegate": {
      "SecretDigest": "REPLACE_WITH_BASE64URL_SHA256_OF_A_HIGH_ENTROPY_CLIENT_SECRET"
    }
  },
  "CIMDScopes": ["inventory:read"],
  "Targets": {
    "https://inventory.example.com": ["inventory:read"]
  },
  "Sessions": {
    "Issuer": "https://login.example.com",
    "Audience": "bastion-consent",
    "JWKSURL": "https://login.example.com/jwks"
  },
  "Exchange": {
    "Issuer": "https://trust.example.com",
    "Audience": "bastion-exchange",
    "JWKSURL": "https://trust.example.com/jwks"
  }
}
```

An upstream identity service supplies the `__Host-bastion_session` cookie on the authorization origin with `Secure`, `HttpOnly`, `Path=/`, and a suitable SameSite policy. The cookie contains a signed `at+jwt` with the configured issuer, sole session audience, tenant, subject, and expiration. The exchange trust configuration accepts `at+jwt` assertions from its configured issuer and audience. Store signing keys and client secrets in a secret manager, use high-entropy confidential-client secrets, and give their unpadded base64url SHA-256 digests to BastionAuth. Schedule expired credential cleanup in tenant-scoped transactions using the `(tenant_id, expires_at)` index.

## Threat model and scope

- A leaked authorization code requires its verifier and exact registered redirect URI. A leaked DPoP-bound token requires the corresponding signing key and a fresh proof. Resource servers verify token claims, `cnf.jkt`, and `ath` using the public JWKS and a shared replay store. They enforce the resource’s audience and application scopes.
- Revocation and token rotation serialize on the same grant. Codes or refresh tokens from earlier generations fail with `invalid_grant` after revocation, including after re-consent. Already issued access tokens expire on their short TTL.
- Missing tenant settings fail closed under RLS. The control assumes the service controls the tenant setting and database role. A compromised application database credential can set tenant context, so the role and connection must remain private.
- Invalid proofs, replay, wrong issuer or audience, JWKS refresh failures, and unavailable state storage cause request failure. A valid cached JWKS remains usable until its cache TTL. Configure an upstream identity provider for interactive login and a resource server for application authorization. Dynamic registration, password grants, login UI, DPoP nonces, and online introspection are outside the service’s scope.

## Verify and benchmark

Set `DATABASE_URL` to a disposable PostgreSQL 16 instance with an integration-test role allowed to create schemas and roles. The integration test creates a temporary schema and authenticates queries as a restricted role. Without this variable, the protocol tests run against the in-memory store.

```sh
go test -race -v ./...
go run ./cmd/migrationlint ./migrations
go run ./benchmarks/run_bench.go -requests 4000 -workers 16
```

The benchmark uses a loopback HTTP server, real token signatures, a served JWKS, unique DPoP proofs, and the in-memory replay store. Throughput and latency come from the concurrent HTTP run. Allocations per operation come from Go’s `testing.Benchmark` and include both HTTP peers. [Measured results](benchmarks/RESULTS.md)

The Wave 3 run completed 4,000 token exchange requests with 16 workers and zero failures. It measured 3,861.18 requests/s, with p50 at 3.446477 ms, p95 at 8.190801 ms, and p99 at 10.952736 ms. The PostgreSQL-backed race suite passed 15 tests and 87 subtests with zero data race reports.
