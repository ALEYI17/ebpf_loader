package metrics

import "github.com/prometheus/client_golang/prometheus"

var(
  EventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "infrasight",
			Subsystem: "tracer",
			Name:      "events_total",
			Help:      "Total number of events received from eBPF tracers.",
		},
		[]string{"tracer"},
	)

  ErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "infrasight",
			Subsystem: "tracer",
			Name:      "errors_total",
			Help:      "Total number of tracer errors (e.g. decoding, ringbuffer issues).",
		},
		[]string{"tracer", "type"},
	)
)
