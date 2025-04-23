package opentracer

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type Open_event Opentracer open_tracer.bpf.c
