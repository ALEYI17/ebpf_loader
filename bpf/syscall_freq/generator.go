package syscallfreq

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type syscall_key SysFreqtracer syscall_freq_tracer.bpf.c
