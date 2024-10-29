package metrics

import "github.com/prometheus/client_golang/prometheus"

// Metrics for Prometheus
var (
	RequestCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nes_lb_requests_total",
			Help: "Total number of requests handled by the load balancer",
		},
		[]string{"route", "status", "protocol"},
	)

	RequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "nes_lb_request_duration_seconds",
			Help:    "Request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"route"},
	)

	ActiveConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "nes_lb_active_connections",
			Help: "Number of active connections",
		},
	)
)
