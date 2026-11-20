# RFC 001 — Token exchange and row-level security

## Exchange authorization

The token endpoint authenticates the calling OAuth client before processing either input. The exchange service validates each input JWT using the configured issuer, exact audience, signature, expiry, tenant, and subject. Ed25519, P-256 ECDSA, and RSA with at least 2048 bits are accepted through the EdDSA, ES256, and RS256 algorithms respectively. The verifier caches public signing keys by `kid` for one minute. A cache miss may refresh the key set early. Refresh attempts are rate limited per JWKS endpoint. The configured JWKS endpoint is fixed and HTTP redirects are disabled by the service configuration.

The actor subject must match the authenticated confidential client ID. The subject token’s `may_act` must name that actor. If present, its issuer must also match. Subject and actor DPoP bindings, when present, must match the current proof. The endpoint accepts exact scope strings and rejects wildcards. Every requested scope must appear in each of the subject scopes, actor scopes, and configured target scopes. When the request omits scope, the service uses the intersection of those three sets. Downstream tokens have one audience, the subject’s original identity, the current actor followed by the subject’s established `act` chain, and a lifetime limited by both input expirations and sixty seconds. Delegation authority is evaluated from the current subject token and is not inherited from historical actors.

## Grant serialization

All credentials carry a grant generation and are looked up by a SHA-256 digest. PostgreSQL locks the grant row with `SELECT … FOR UPDATE` before checking validity and consuming a credential. Consent, generation increment, and code or refresh rotation are each transactionally atomic. If exchange acquires the lock first and commits, it can mint an access token, but the subsequent revocation invalidates its refresh token. If revocation takes the lock first, exchange fails with `invalid_grant`. A refresh token remains bound to the key used on its original code exchange. Re-consent activates the new generation and never revives an earlier one.

## Tenant context and DPoP replay

Primary and lookup keys are tenant-prefixed. The service begins a transaction and uses `SET LOCAL app.tenant_id` with a tenant literal quoted by pgx. PostgreSQL resets local state on commit or rollback. Policies use the scalar-subquery form of `current_setting` for both visibility and writes. `FORCE ROW LEVEL SECURITY` applies the policies to table owners as well. Service startup rejects superuser and `BYPASSRLS` roles.

The DPoP verifier validates the signed proof’s type, public JWK, RFC 7638 thumbprint, method, normalized URI, and sixty-second issuance window. Resource requests also verify the exact encoded access token’s hash and require the token thumbprint to match the proof. An atomic unique key on tenant, thumbprint and `jti` prevents replay across service replicas using the same database. Entries expire after the proof’s acceptance window. Each successful claim can evict a bounded batch of expired entries, and a claim for an expired identifier replaces that entry atomically. The token endpoint requires a fresh proof without an `ath` claim because the request is authenticated as an OAuth grant, rather than as a resource request.

## Online schema changes

Migrations run lexically in autocommit mode with positive lock and statement timeouts set per file. Indexes on existing tables use `CREATE INDEX CONCURRENTLY`. To promote an existing nullable column, add a named `CHECK (column IS NOT NULL) NOT VALID`, backfill as needed, validate the check in its own statement, then use `SET NOT NULL` in a separate statement. The AST linter checks these guardrails. Operators still review lock behavior for changes such as rewrites, foreign keys and partition maintenance.

- [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)
- [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)
- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)
