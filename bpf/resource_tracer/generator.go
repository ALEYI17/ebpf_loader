package resourcetracer

import (
	"ebpf_loader/internal/grpc/pb"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type resource_event_t Resourcetracer resource_tracer.bpf.c

func GenerateGrpcMessage(raw ResourcetracerResourceEventT, nodeName string) *pb.EbpfEvent{
  
  fmt.Printf("comm: %s , pid: %d ,cpu ns: %d, rss: %d \n", unix.ByteSliceToString(raw.Comm[:]),raw.Pid,raw.CpuNs,raw.RssBytes)

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
		EventType:       "ptrace",
		NodeName:        nodeName,
		TimestampUnixMs: time.Now().UnixMilli(),
    Payload: &pb.EbpfEvent_Resource{
      Resource: &pb.ResourceEvent{
        CpuNs: raw.CpuNs,
        RssBytes: raw.RssBytes,
      },
    },
  }

  
}
