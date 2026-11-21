SET lock_timeout = '2s';
SET statement_timeout = '30s';

CREATE TABLE access_tokens (
    tenant_id text,
    digest text,
    jti text CHECK (jti IS NOT NULL),
    user_id text CHECK (user_id IS NOT NULL),
    client_id text CHECK (client_id IS NOT NULL),
    generation bigint CHECK (generation > 0 AND generation IS NOT NULL),
    audience text CHECK (audience IS NOT NULL),
    scope text CHECK (scope IS NOT NULL),
    jkt text CHECK (jkt IS NOT NULL),
    expires_at timestamptz CHECK (expires_at IS NOT NULL),
    revoked boolean DEFAULT false CHECK (revoked IS NOT NULL),
    PRIMARY KEY (tenant_id, digest),
    UNIQUE (tenant_id, jti),
    FOREIGN KEY (tenant_id, user_id, client_id) REFERENCES grants
);
ALTER TABLE access_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_access_tokens ON access_tokens
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant_id', true)));

CREATE INDEX CONCURRENTLY access_tokens_grant_idx ON access_tokens (tenant_id, user_id, client_id, generation);
CREATE INDEX CONCURRENTLY access_tokens_expiry_idx ON access_tokens (tenant_id, expires_at);
