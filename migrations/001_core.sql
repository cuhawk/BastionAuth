SET lock_timeout = '2s';
SET statement_timeout = '30s';

CREATE TABLE grants (
    tenant_id text,
    user_id text,
    client_id text,
    generation bigint DEFAULT 1 CHECK (generation > 0 AND generation IS NOT NULL),
    active boolean DEFAULT true CHECK (active IS NOT NULL),
    PRIMARY KEY (tenant_id, user_id, client_id)
);
CREATE TABLE credentials (
    tenant_id text,
    digest text,
    user_id text CHECK (user_id IS NOT NULL),
    client_id text CHECK (client_id IS NOT NULL),
    generation bigint CHECK (generation > 0 AND generation IS NOT NULL),
    expires_at timestamptz CHECK (expires_at IS NOT NULL),
    payload jsonb CHECK (payload IS NOT NULL),
    PRIMARY KEY (tenant_id, digest),
    FOREIGN KEY (tenant_id, user_id, client_id) REFERENCES grants
);
ALTER TABLE grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE grants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_grants ON grants
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant_id', true)));
ALTER TABLE credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_credentials ON credentials
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant_id', true)));

CREATE TABLE dpop_replays (
    tenant_id text,
    thumbprint text,
    jti text,
    expires_at timestamptz CHECK (expires_at IS NOT NULL),
    PRIMARY KEY (tenant_id, thumbprint, jti)
);
ALTER TABLE dpop_replays ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpop_replays FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_replays ON dpop_replays
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant_id', true)));
