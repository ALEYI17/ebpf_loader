package mmaptracer

import (
	"ebpf_loader/internal/grpc/pb"
	"time"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type mmap_event_t Mmaptracer mmap_tracer.bpf.c

func GenerateGrpcMessage(raw MmaptracerMmapEventT, nodeName string) *pb.EbpfEvent{
  
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
		EventType:       "mmap", 
		NodeName:        nodeName,
    TimestampUnixMs: time.Now().UnixMilli(),
    Payload: &pb.EbpfEvent_Mmap{
      Mmap: &pb.MmapEvent{
        Addr: raw.Addr,
        Len: raw.Len,
        Prot: raw.Prot,
        Flags: raw.Flags,
        Fd: raw.Fd,
        Off: raw.Off,
        ReturnCode: raw.Ret,
      },
    },
	}

}
