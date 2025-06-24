package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	MessagesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "infrasight",
			Subsystem: "grpc",
			Name:      "messages_sent_total",
			Help:      "Total number of gRPC messages sent.",
		},
		[]string{"tracer", "status"}, // status: success | error
	)

	SendLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "infrasight",
			Subsystem: "grpc",
			Name:      "send_latency_seconds",
			Help:      "Histogram of gRPC send latencies.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"tracer"},
	)
)
