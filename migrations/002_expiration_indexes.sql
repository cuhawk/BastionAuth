SET lock_timeout = '2s';
SET statement_timeout = '30s';

CREATE INDEX CONCURRENTLY credentials_grant_idx ON credentials (tenant_id, user_id, client_id);
CREATE INDEX CONCURRENTLY dpop_expiry_idx ON dpop_replays (tenant_id, expires_at);
CREATE INDEX CONCURRENTLY credentials_expiry_idx ON credentials (tenant_id, expires_at);
