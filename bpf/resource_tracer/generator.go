package resourcetracer

import (
	"ebpf_loader/internal/grpc/pb"
	"time"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type resource_event_t Resourcetracer resource_tracer.bpf.c

func GenerateGrpcMessage(raw ResourcetracerResourceEventT, nodeName string, intervalSec int) *pb.EbpfEvent{

  durNs := float64(intervalSec) * 1e9
  cpuPercent := (float64(raw.CpuNs) / durNs) * 100.0

  bytesReadRate := float64(raw.BytesRead) / float64(intervalSec)
  bytesWrittenRate := float64(raw.BytesWritten) / float64(intervalSec)

  mmapRate := float64(raw.VmMmapBytes) / float64(intervalSec)
  munmapRate := float64(raw.VmMunmapBytes) / float64(intervalSec)
  brkGrowRate := float64(raw.VmBrkGrowBytes) / float64(intervalSec)
  brkShrinkRate := float64(raw.VmBrkShrinkBytes) / float64(intervalSec)


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
          CpuNs:            cpuPercent,
          UserFaults:       raw.UserFaults,
          KernelFaults:     raw.KernelFaults,
          VmMmapBytes:      mmapRate,
          VmMunmapBytes:    munmapRate,
          VmBrkGrowBytes:   brkGrowRate,
          VmBrkShrinkBytes: brkShrinkRate,
          BytesWritten:     bytesWrittenRate,
          BytesRead:        bytesReadRate,
          IsActive: isActive,
      },
    },
  }

  
}
