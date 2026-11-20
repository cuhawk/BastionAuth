package oauth

import (
	"net/http"
	"strings"

	"github.com/cuhawk/BastionAuth/internal/exchange"
	"github.com/felixge/httpsnoop"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

func instrument(mux *http.ServeMux) http.Handler {
	registry := prometheus.NewRegistry()
	exporter, err := otelprom.New(otelprom.WithRegisterer(registry), otelprom.WithoutScopeInfo(), otelprom.WithoutTargetInfo())
	if err != nil {
		panic(err) // A private, empty registry has no conflicting collectors.
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	meter := provider.Meter("github.com/cuhawk/BastionAuth/internal/oauth")
	duration, err := meter.Float64Histogram("http.request.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Duration of HTTP server requests."),
		metric.WithExplicitBucketBoundaries(.005, .01, .025, .05, .075, .1, .25, .5, .75, 1, 2.5, 5, 7.5, 10))
	if err != nil {
		panic(err)
	}
	oauthOutcomes := outcomeCounter(meter, "oauth.requests", "Completed OAuth requests.")
	exchangeOutcomes := outcomeCounter(meter, "oauth.exchange.requests", "Completed OAuth token exchange requests.")
	parOutcomes := outcomeCounter(meter, "oauth.par.requests", "Completed pushed authorization requests.")
	mux.Handle("GET /metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)
		if pattern == "GET /metrics" {
			mux.ServeHTTP(w, r)
			return
		}
		captured := httpsnoop.CaptureMetrics(mux, w, r)
		method := r.Method
		switch method {
		case "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE":
		default:
			method = "_OTHER"
		}
		_, route, _ := strings.Cut(pattern, " ")
		attrs := []attribute.KeyValue{
			attribute.String("http.request.method", method),
			attribute.Int("http.response.status_code", captured.Code),
		}
		if route != "" {
			attrs = append(attrs, attribute.String("http.route", route))
		}
		duration.Record(r.Context(), captured.Duration.Seconds(), metric.WithAttributes(attrs...))
		switch route {
		case "/oauth/authorize", "/oauth/token", "/oauth/par", "/oauth/grant/revoke":
			outcome := "success"
			switch {
			case captured.Code >= 500:
				outcome = "server_error"
			case captured.Code >= 400:
				outcome = "client_error"
			case route == "/oauth/authorize" && captured.Code == http.StatusSeeOther && r.PostForm.Get("decision") == "deny":
				outcome = "denied"
			}
			oauthOutcomes.Add(r.Context(), 1, metric.WithAttributes(attribute.String("http.route", route), attribute.String("outcome", outcome)))
			option := metric.WithAttributes(attribute.String("outcome", outcome))
			switch {
			case route == "/oauth/par":
				parOutcomes.Add(r.Context(), 1, option)
			case route == "/oauth/token" && r.PostForm.Get("grant_type") == exchange.GrantType:
				exchangeOutcomes.Add(r.Context(), 1, option)
			}
		}
	})
}

func outcomeCounter(meter metric.Meter, name, description string) metric.Int64Counter {
	counter, err := meter.Int64Counter(name, metric.WithDescription(description))
	if err != nil {
		panic(err)
	}
	return counter
}
