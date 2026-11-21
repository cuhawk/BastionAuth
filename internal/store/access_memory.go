package store

import (
	"context"
	"time"
)

const spentRefresh = "spent_refresh_token"

type accessEntry struct {
	token      AccessToken
	generation int64
}

func (m *Memory) saveAccess(tenant string, token AccessToken, generation int64) {
	now := time.Now()
	if !now.Before(m.nextAccessSweep) {
		for key, entry := range m.access {
			if !now.Before(entry.token.Expires) {
				delete(m.access, key)
				delete(m.accessByJTI, credentialKey{key.tenant, entry.token.JTI})
			}
		}
		for key, entry := range m.credentials {
			if !now.Before(entry.credential.Expires) {
				delete(m.credentials, key)
			}
		}
		m.nextAccessSweep = now.Add(time.Minute)
	}
	key := credentialKey{tenant, token.Digest}
	m.access[key] = accessEntry{token: token, generation: generation}
	m.accessByJTI[credentialKey{tenant, token.JTI}] = key
}

func (m *Memory) SaveAccess(ctx context.Context, tenant string, token AccessToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	key := grantKey{tenant, token.User, token.Client}
	g, exists := m.grants[key]
	if !exists {
		g = grant{generation: 1, active: true}
		m.grants[key] = g
	}
	if !g.active {
		return ErrInvalid
	}
	m.saveAccess(tenant, token, g.generation)
	return nil
}

func (m *Memory) LookupAccess(ctx context.Context, tenant, digest string) (AccessToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return AccessToken{}, err
	}
	entry, ok := m.access[credentialKey{tenant, digest}]
	if !ok || m.accessRevoked(tenant, entry) || !time.Now().Before(entry.token.Expires) {
		return AccessToken{}, ErrInvalid
	}
	return entry.token, nil
}

func (m *Memory) AccessRevoked(ctx context.Context, tenant, jti string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	key, ok := m.accessByJTI[credentialKey{tenant, jti}]
	entry := m.access[key]
	return ok && time.Now().Before(entry.token.Expires) && m.accessRevoked(tenant, entry), nil
}

func (m *Memory) accessRevoked(tenant string, entry accessEntry) bool {
	g := m.grants[grantKey{tenant, entry.token.User, entry.token.Client}]
	return !g.active || g.generation != entry.generation
}

func (m *Memory) revokeGrant(key grantKey) {
	g := m.grants[key]
	if !g.active {
		return
	}
	g.generation++
	g.active = false
	m.grants[key] = g
}

func (m *Memory) RevokeToken(ctx context.Context, tenant, client, digest string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	key := credentialKey{tenant, digest}
	now := time.Now()
	if entry, ok := m.access[key]; ok && entry.token.Client == client && now.Before(entry.token.Expires) {
		g := grantKey{tenant, entry.token.User, client}
		if m.grants[g].generation == entry.generation {
			m.revokeGrant(g)
		}
	}
	if entry, ok := m.credentials[key]; ok && entry.credential.Client == client && now.Before(entry.credential.Expires) &&
		(entry.credential.Kind == "refresh_token" || entry.credential.Kind == spentRefresh) {
		g := grantKey{tenant, entry.credential.User, client}
		if m.grants[g].generation == entry.generation {
			m.revokeGrant(g)
		}
	}
	return nil
}
