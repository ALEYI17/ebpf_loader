package ptracetracer

import (
	"ebpf_loader/internal/grpc/pb"
	"time"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type ptrace_event_t Ptracetracer ptrace_tracer.bpf.c

func GenerateGrpcMessage(raw PtracetracerPtraceEventT, nodeName string) *pb.EbpfEvent{

  return &pb.EbpfEvent{
		Pid:             raw.Pid,
		Uid:             raw.Uid,
		Gid:             raw.Gid,
		Ppid:            raw.Ppid,
		UserPid:         raw.UserPid,
		UserPpid:        raw.UserPpid,
		CgroupId:        raw.CgroupId,
		CgroupName:      unix.ByteSliceToString(raw.CgroupName[:]),
		Comm:            unix.ByteSliceToString(raw.Comm[:]),
		TimestampNs:     raw.TimestampNs,
		TimestampNsExit: raw.TimestampNsExit,
		LatencyNs:       raw.Latency,
		EventType:       "accept",
		NodeName:        nodeName,
		TimestampUnixMs: time.Now().UnixMilli(),
		Payload: &pb.EbpfEvent_Ptrace{ // oneof for NetworkEvent
			Ptrace: &pb.PtraceEvent{
				ReturnCode: raw.Ret,
				Addr: raw.Addr,
        TargetPid: raw.PidPtrace,
        Request: raw.Request,
        Data: raw.Data,
			},
		},
	}
}
