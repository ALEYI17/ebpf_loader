package resourcetracer

import (
	"ebpf_loader/internal/grpc/pb"
	"time"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type resource_event_t Resourcetracer resource_tracer.bpf.c

func GenerateGrpcMessage(raw ResourcetracerResourceEventT, nodeName string) *pb.EbpfEvent{

  // fmt.Printf(
  //       "comm: %s, pid: %d, cpu_ns: %d, user_faults: %d, kernel_faults: %d, "+
  //           "vm_mmap_bytes: %d, vm_munmap_bytes: %d, vm_brk_grow_bytes: %d, "+
  //           "vm_brk_shrink_bytes: %d, bytes_written: %d, bytes_read: %d, last_seen_ns: %d\n",
  //       unix.ByteSliceToString(raw.Comm[:]),
  //       raw.Pid,
  //       raw.CpuNs,
  //       raw.UserFaults,
  //       raw.KernelFaults,
  //       raw.VmMmapBytes,
  //       raw.VmMunmapBytes,
  //       raw.VmBrkGrowBytes,
  //       raw.VmBrkShrinkBytes,
  //       raw.BytesWritten,
  //       raw.BytesRead,
  //       raw.LastSeenNs,
  //   )

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
      },
    },
  }

  
}
