package syscallfreq

import (
	"ebpf_loader/internal/grpc/pb"
	"time"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type syscall_key SysFreqtracer syscall_freq_tracer.bpf.c

func GenerateGrpcMessage(raw SysFreqtracerSyscallKey,count uint64, nodeName string) *pb.EbpfEvent{

  return &pb.EbpfEvent{
    Pid: raw.Pid,
    EventType: "sys_freq",
    NodeName: nodeName,
    TimestampUnixMs: time.Now().UnixMilli(),
    Payload: &pb.EbpfEvent_SysFreq{
      SysFreq: &pb.SysFreqEvent{
        SyscallId: raw.SyscallNr,
        Count: count,
      },
    },
  }
}
