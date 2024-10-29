package metrics

import "github.com/prometheus/client_golang/prometheus"

// Metrics for Prometheus
var (
	ServiceCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "nes_services_count",
			Help: "Total number of services served by nes",
		},
	)

	ServiceContainerCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nes_service_container_count",
			Help: "Total number of containers served by a service",
		},
		[]string{"service", "container"},
	)
)
