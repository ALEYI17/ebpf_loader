package execvetracer

import (
	"ebpf_loader/internal/grpc/pb"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type trace_syscall_event  Execvetracer execve_tracer.bpf.c

func GenerateGrpcMessage(raw ExecvetracerTraceSyscallEvent, nodeName string) *pb.EbpfEvent {
  return &pb.EbpfEvent{
		Pid:             raw.Pid,
		Uid:             raw.Uid,
		Comm:            unix.ByteSliceToString(raw.Comm[:]),
		Filename:        unix.ByteSliceToString(raw.Filename[:]),
		ReturnCode:      raw.Ret,
		TimestampNs:     raw.TimestampNs,
		TimestampNsExit: raw.TimestampNsExit,
		LatencyNs:       raw.Latency,
		EventType:       "execve",
		NodeName:        nodeName,
	}
}
