package ptracetracer

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type ptrace_event_t Ptracetracer ptrace_tracer.bpf.c
