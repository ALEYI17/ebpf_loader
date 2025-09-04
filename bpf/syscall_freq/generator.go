package syscallfreq

import (
	"ebpf_loader/internal/grpc/pb"
	//"fmt"
	"time"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type syscall_key SysFreqtracer syscall_freq_tracer.bpf.c

func GenerateGrpcMessage(raw SysFreqtracerSyscallKey,count uint64,meta *SysFreqtracerProcessMetadataT ,nodeName string) *pb.EbpfEvent{

  //fmt.Printf("pid: %d , sys_nr: %d , count: %d", raw.Pid,raw.SyscallNr,count)

  return &pb.EbpfEvent{
    Pid: raw.Pid,
    Uid: meta.Uid,
    Gid: meta.Gid,
    Ppid: meta.Ppid,
    UserPid: meta.UserPid,
    UserPpid: meta.UserPpid,
    CgroupId: meta.CgroupId,
    CgroupName: unix.ByteSliceToString(meta.CgroupName[:]), 
    Comm: unix.ByteSliceToString(meta.Comm[:]),
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
