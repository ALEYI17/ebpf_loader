package opentracer

import (
	"ebpf_loader/internal/grpc/pb"
	"time"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type trace_syscall_event  Opentracer open_tracer.bpf.c


func GenerateGrpcMessage(raw OpentracerTraceSyscallEvent, nodeName string) *pb.EbpfEvent {

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
		EventType:       "open", 
		NodeName:        nodeName,
    TimestampUnixMs: time.Now().UnixMilli(),
    Payload: &pb.EbpfEvent_Snoop{
      Snoop: &pb.SnooperEvent{
        Filename: unix.ByteSliceToString(raw.Filename[:]),
        ReturnCode: raw.Ret,
      },
    },
	}
}
