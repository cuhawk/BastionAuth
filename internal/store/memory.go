package store

import (
	"context"
	"sync"
	"time"
)

type grantKey struct{ tenant, user, client string }
type credentialKey struct{ tenant, digest string }
type proofKey struct{ tenant, key, jti string }
type grant struct {
	generation int64
	active     bool
}
type entry struct {
	credential Credential
	generation int64
}

type Memory struct {
	mu              sync.Mutex
	access          map[credentialKey]accessEntry
	accessByJTI     map[credentialKey]credentialKey
	nextAccessSweep time.Time
	grants          map[grantKey]grant
	credentials     map[credentialKey]entry
	proofs          map[proofKey]time.Time
	nextSweep       time.Time
	pushed          map[credentialKey]PushedRequest
	nextPARSweep    time.Time
}

func NewMemory() *Memory {
	return &Memory{
		grants:      make(map[grantKey]grant),
		credentials: make(map[credentialKey]entry),
		access:      make(map[credentialKey]accessEntry),
		accessByJTI: make(map[credentialKey]credentialKey),
		pushed:      make(map[credentialKey]PushedRequest),
		proofs:      make(map[proofKey]time.Time),
	}
}

func (m *Memory) Consent(ctx context.Context, tenant, digest string, c Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	k := grantKey{tenant, c.User, c.Client}
	g := m.grants[k]
	if g.generation == 0 {
		g.generation = 1
	}
	g.active = true
	m.grants[k] = g
	m.credentials[credentialKey{tenant, digest}] = entry{c, g.generation}
	return nil
}

func (m *Memory) Revoke(ctx context.Context, tenant, user, client string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	m.revokeGrant(grantKey{tenant, user, client})
	return nil
}

func (m *Memory) Rotate(ctx context.Context, tenant, oldDigest, newDigest string, issue func(Credential) (Credential, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	oldKey := credentialKey{tenant, oldDigest}
	e, ok := m.credentials[oldKey]
	g := m.grants[grantKey{tenant, e.credential.User, e.credential.Client}]
	if !ok || !g.active || e.generation != g.generation || e.credential.Kind == spentRefresh {
		return ErrInvalid
	}
	next, err := issue(e.credential)
	if err != nil {
		return err
	}
	if next.Access != nil {
		m.saveAccess(tenant, *next.Access, e.generation)
		next.Access = nil
	}
	if e.credential.Kind == "refresh_token" {
		e.credential.Kind = spentRefresh
		m.credentials[oldKey] = e
	} else {
		delete(m.credentials, oldKey)
	}
	m.credentials[credentialKey{tenant, newDigest}] = entry{next, e.generation}
	return nil
}

func (m *Memory) ClaimProof(ctx context.Context, tenant, key, jti string, now, expires time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !now.Before(m.nextSweep) {
		for k, expiry := range m.proofs {
			if !now.Before(expiry) {
				delete(m.proofs, k)
			}
		}
		m.nextSweep = now.Add(time.Minute)
	}
	k := proofKey{tenant, key, jti}
	if now.Before(m.proofs[k]) {
		return false, nil
	}
	m.proofs[k] = expires
	return true, nil
}
