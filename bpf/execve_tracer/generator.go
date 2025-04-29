package execvetracer

import (
	"ebpf_loader/internal/grpc/pb"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type Exec_event Execvetracer execve_tracer.bpf.c

func GenerateGrpcMessage(raw ExecvetracerExecEvent, nodeName string) *pb.EbpfEvent {
	return &pb.EbpfEvent{
		NodeName: nodeName,
		Event: &pb.EbpfEvent_ExecveEvent{
			ExecveEvent: &pb.ExecveEvent{
				Pid:             raw.Pid,
				Uid:             raw.Uid,
				Comm:            unix.ByteSliceToString(raw.Comm[:]),
				Filename:        unix.ByteSliceToString(raw.Filename[:]),
				TimestampNsExit: raw.TimestampNsExit,
				ReturnCode:      raw.Ret,
				TimestampNs:     raw.TimestampNs,
				LatencyNs:       raw.Latency,
			},
		},
	}
}
