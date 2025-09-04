package resourcetracer

import (
	"ebpf_loader/internal/grpc/pb"
	"time"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type resource_event_t Resourcetracer resource_tracer.bpf.c

func GenerateGrpcMessage(raw ResourcetracerResourceEventT, nodeName string) *pb.EbpfEvent{

  var isActive uint32

  if raw.CpuNs > 0 || raw.UserFaults > 0|| raw.KernelFaults > 0 ||
      raw.VmMmapBytes > 0 || raw.VmMunmapBytes > 0 || raw.VmBrkGrowBytes >0 ||
      raw.VmBrkShrinkBytes > 0 || raw.BytesRead > 0 || raw.BytesWritten > 0 {
    isActive = 1
  }else{
    isActive = 0
  }
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
		EventType:       "resource",
		NodeName:        nodeName,
		TimestampUnixMs: time.Now().UnixMilli(),
    Payload: &pb.EbpfEvent_Resource{
      Resource: &pb.ResourceEvent{
          CpuNs:            raw.CpuNs,
          UserFaults:       raw.UserFaults,
          KernelFaults:     raw.KernelFaults,
          VmMmapBytes:      raw.VmMmapBytes,
          VmMunmapBytes:    raw.VmMunmapBytes,
          VmBrkGrowBytes:   raw.VmBrkGrowBytes,
          VmBrkShrinkBytes: raw.VmBrkShrinkBytes,
          BytesWritten:     raw.BytesWritten,
          BytesRead:        raw.BytesRead,
          IsActive: isActive,
      },
    },
  }

  
}
