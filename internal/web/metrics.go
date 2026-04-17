package web

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// User Mettrics
var PostsTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "user_posts_total",
	Help: "The total posts recorded",
})

var NewRegisteredUsers = promauto.NewCounter(prometheus.CounterOpts{
	Name: "new_registered_users",
	Help: "Total amount of registered users",
})

// HTTP Errors
var InternalServerErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "total_server_errors",
	Help: "Tracks Server Errors, and the Http Request that triggered it",
}, []string{"url", "method"})

var InvalidRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "total_invalid_request",
	Help: "The total amount of 400-codes thrown",
}, []string{"url", "error msg"})

var (
	httpRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of HTTP requests processed.",
	}, []string{"method", "path", "status"})

	httpRequestDurationMs = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_request_duration_milliseconds",
		Help:    "Request duration distribution in milliseconds.",
		Buckets: []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000},
	}, []string{"method", "path"})
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" || r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		path := chi.RouteContext(r.Context()).RoutePattern()
		if path == "" {
			path = "unknown"
		}

		status := strconv.Itoa(rec.status)
		httpRequestsTotal.WithLabelValues(r.Method, path, status).Inc()
		httpRequestDurationMs.WithLabelValues(r.Method, path).
			Observe(float64(time.Since(start).Milliseconds()))
	})
}
