package store_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cuhawk/BastionAuth/internal/store"
)

func TestMemoryPushedRequests(t *testing.T) { checkPushedRequests(t, store.NewMemory()) }

func checkPushedRequests(t *testing.T, backend store.Store) {
	t.Helper()
	ctx := t.Context()
	request := store.PushedRequest{Client: "client", Form: "state=original", Expires: time.Now().Add(time.Minute)}
	if err := backend.SavePushedRequest(ctx, "alpha", "reference", request); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ tenant, client string }{{"beta", "client"}, {"alpha", "other-client"}} {
		if _, err := backend.TakePushedRequest(ctx, test.tenant, test.client, "reference"); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("incorrect tenant or client accepted: %v", err)
		}
	}
	expired := request
	expired.Expires = time.Now().Add(-time.Second)
	if err := backend.SavePushedRequest(ctx, "alpha", "expired", expired); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.TakePushedRequest(ctx, "alpha", "client", "expired"); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("expired reference accepted: %v", err)
	}
	// Leave a second tenant's live row for the integration test's RLS assertion.
	if err := backend.SavePushedRequest(ctx, "beta", "reference", request); err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			form, err := backend.TakePushedRequest(ctx, "alpha", "client", "reference")
			if err == nil && form == request.Form {
				winners.Add(1)
			} else if !errors.Is(err, store.ErrInvalid) {
				t.Errorf("unexpected consumption: %q %v", form, err)
			}
		})
	}
	wg.Wait()
	if got := winners.Load(); got != 1 {
		t.Fatalf("successful consumes: got %d, want 1", got)
	}
}
