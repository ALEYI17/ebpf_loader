package connecttracer

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type socket_event_t   Connecttracer connect_tracer.bpf.c
