// Command run_bench measures a real OAuth token endpoint over loopback HTTP.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cuhawk/BastionAuth/internal/dpop"
	"github.com/cuhawk/BastionAuth/internal/exchange"
	"github.com/cuhawk/BastionAuth/internal/oauth"
	"github.com/cuhawk/BastionAuth/internal/store"
	"github.com/cuhawk/BastionAuth/internal/testutil"
)

func main() {
	requests := flag.Int("requests", 4000, "parallel HTTP load request count")
	workers := flag.Int("workers", 16, "concurrent HTTP clients")
	flag.Parse()
	if *requests < 1 || *workers < 1 {
		log.Fatal("requests and workers must be positive")
	}
	keys := testutil.NewKeys()
	jwks := keys.JWKS()
	defer jwks.Close()
	signer := keys.Signer("at+jwt", false)
	proofSigner := testutil.NewKeys().Signer("dpop+jwt", true)
	server := httptest.NewUnstartedServer(nil)
	origin := "http://" + server.Listener.Addr().String()
	const issuer = "https://issuer.example.test"
	subject := testutil.Access(signer, issuer, "tenant", "user", "exchange", "read", &exchange.Actor{Subject: "delegate"}, nil)
	actor := testutil.Access(signer, issuer, "tenant", "delegate", "exchange", "read", nil, nil)
	mem := store.NewMemory()
	secret := store.Secret()
	service := exchange.Service{
		Verifier: exchange.Verifier{Keys: &exchange.JWKS{URL: jwks.URL}, Issuer: issuer, Audience: "exchange"},
		Issuer:   exchange.Issuer{Name: issuer, Signer: signer},
		Targets:  map[string][]string{"inventory": {"read"}},
	}
	s := oauth.Server{Tenant: "tenant", Origin: origin, Store: mem, Clients: map[string]oauth.Client{"delegate": {SecretDigest: store.Digest(secret)}}, Exchange: service, DPoP: dpop.Verifier{Store: mem}}
	server.Config.Handler = s.Handler()
	server.Start()
	defer server.Close()
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, MaxIdleConns: *workers, MaxIdleConnsPerHost: *workers}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	target := server.URL + "/oauth/token"
	form := url.Values{"grant_type": {exchange.GrantType}, "subject_token": {subject}, "subject_token_type": {exchange.AccessType}, "actor_token": {actor}, "actor_token_type": {exchange.AccessType}, "audience": {"inventory"}, "scope": {"read"}}.Encode()
	send := func(proof string) error {
		req, err := http.NewRequest("POST", target, strings.NewReader(form))
		if err != nil {
			return err
		}
		req.SetBasicAuth("delegate", secret)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("DPoP", proof)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var body struct {
			Access string `json:"access_token"`
			Type   string `json:"token_type"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return err
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			return err
		}
		if resp.StatusCode != 200 || body.Access == "" || body.Type != "DPoP" {
			return fmt.Errorf("token endpoint returned HTTP %d", resp.StatusCode)
		}
		return nil
	}
	proof := func() string { return testutil.Proof(proofSigner, "POST", target, "", store.Secret(), time.Now()) }
	if err := send(proof()); err != nil {
		log.Fatal(err)
	}
	// Pre-sign unique proofs so the load window measures endpoint and transport work.
	proofs := make([]string, *requests)
	for i := range proofs {
		proofs[i] = proof()
	}
	samples := make([]time.Duration, *requests)
	jobs := make(chan int)
	failures := make(chan error, *workers)
	var wg sync.WaitGroup
	for range *workers {
		wg.Go(func() {
			var first error
			for i := range jobs {
				start := time.Now()
				if err := send(proofs[i]); err != nil && first == nil {
					first = err
				}
				samples[i] = time.Since(start)
			}
			if first != nil {
				failures <- first
			}
		})
	}
	start := time.Now()
	for i := range proofs {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	elapsed := time.Since(start)
	close(failures)
	for err := range failures {
		log.Fatal(err)
	}
	slices.Sort(samples)
	percentile := func(p float64) time.Duration { return samples[int(math.Ceil(p*float64(len(samples))))-1] }
	// testing.Benchmark measures allocations in this process, including both HTTP peers.
	measured := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			signed := proof()
			b.StartTimer()
			if err := send(signed); err != nil {
				log.Fatal(err)
			}
		}
	})
	fmt.Printf("Requests/s: %.2f\np50: %s\np95: %s\np99: %s\nAllocations/op: %d\n", float64(*requests)/elapsed.Seconds(), percentile(.50), percentile(.95), percentile(.99), measured.AllocsPerOp())
}
