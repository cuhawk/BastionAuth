package dpop_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cuhawk/BastionAuth/internal/dpop"
	"github.com/cuhawk/BastionAuth/internal/store"
	"github.com/cuhawk/BastionAuth/internal/testutil"
)

func TestDPoPReplayAndBinding(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	v := dpop.Verifier{Store: store.NewMemory(), Now: func() time.Time { return now }}
	signer := testutil.NewKeys().Signer("dpop+jwt", true)
	const target = "https://example.test/resource"
	proof := testutil.Proof(signer, "GET", "https://EXAMPLE.TEST:443/a/../%72esource", "access", "same-id", now)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			_, err := v.Verify(context.Background(), "tenant", proof, "GET", target+"?page=1", "access", "")
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, dpop.ErrProof) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if n := accepted.Load(); n != 1 {
		t.Fatalf("%d accepted; want 1", n)
	}
	for _, test := range []struct {
		name, method, uri, token, binding string
		time                              time.Time
	}{
		{"method", "POST", target, "access", "", now},
		{"uri", "GET", target + "/", "access", "", now},
		{"ath", "GET", target, "different", "", now},
		{"jkt", "GET", target, "access", "different", now},
		{"old", "GET", target, "access", "", now.Add(-61 * time.Second)},
		{"future", "GET", target, "access", "", now.Add(61 * time.Second)},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := testutil.Proof(signer, "GET", target, "access", test.name, test.time)
			if _, err := v.Verify(context.Background(), "tenant", raw, test.method, test.uri, test.token, test.binding); !errors.Is(err, dpop.ErrProof) {
				t.Fatalf("expected invalid proof, got %v", err)
			}
		})
	}
}
