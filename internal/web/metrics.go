package web

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/shirou/gopsutil/v4/cpu"
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

// System Metrics
var (
	cpuGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "minitwit_cpu_load_percent",
		Help: "Current load of the CPU in percent.",
	})

	responseCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "minitwit_http_responses_total",
		Help: "The count of HTTP responses sent.",
	})

	reqDurationHistogram = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "minitwit_request_duration_milliseconds",
		Help: "Request duration distribution.",
	})
)

func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		percents, err := cpu.Percent(0, false)
		if err == nil && len(percents) > 0 {
			cpuGauge.Set(percents[0])
		}

		next.ServeHTTP(w, r)

		responseCounter.Inc()
		elapsedMs := float64(time.Since(start).Milliseconds())
		reqDurationHistogram.Observe(elapsedMs)
	})
}
