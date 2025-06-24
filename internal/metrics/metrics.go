package metrics

import "github.com/prometheus/client_golang/prometheus"

func RegisterAll() {
	prometheus.MustRegister(
		EventsTotal,
		ErrorsTotal,
		MessagesSent,
		SendLatency,
    CacheMisses,
    CacheHits,
	)
}
