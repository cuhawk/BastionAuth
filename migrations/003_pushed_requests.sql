SET lock_timeout = '2s';
SET statement_timeout = '30s';

CREATE TABLE pushed_requests (
    tenant_id text,
    digest text,
    client_id text CHECK (client_id IS NOT NULL),
    expires_at timestamptz CHECK (expires_at IS NOT NULL),
    form text CHECK (form IS NOT NULL),
    PRIMARY KEY (tenant_id, digest)
);
ALTER TABLE pushed_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE pushed_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_pushed_requests ON pushed_requests
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant_id', true)));
CREATE INDEX CONCURRENTLY pushed_requests_expiry_idx ON pushed_requests (tenant_id, expires_at);
