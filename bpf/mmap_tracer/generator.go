package mmaptracer

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type mmap_event_t Mmaptracer mmap_tracer.bpf.c
