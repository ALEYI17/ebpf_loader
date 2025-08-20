package resourcetracer

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type resource_event_t Resourcetracer resource_tracer.bpf.c
