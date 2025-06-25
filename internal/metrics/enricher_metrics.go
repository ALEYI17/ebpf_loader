package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	CacheHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "infrasight",
			Subsystem: "enricher",
			Name:      "cache_hits_total",
			Help:      "Total number of cache hits during container enrichment.",
		},
		[]string{"source"}, // e.g. "container", "user"
	)

	CacheMisses = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "infrasight",
			Subsystem: "enricher",
			Name:      "cache_misses_total",
			Help:      "Total number of cache misses during container enrichment.",
		},
		[]string{"source"},
	)
)
