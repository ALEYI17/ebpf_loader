package mounttracer

import (
	"ebpf_loader/internal/grpc/pb"
	"time"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type mount_event_t Mounttracer mount_tracer.bpf.c

func GenerateGrpcMessage(raw MounttracerMountEventT, nodeName string) *pb.EbpfEvent{
  
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
		EventType:       "mount",
		NodeName:        nodeName,
		TimestampUnixMs: time.Now().UnixMilli(),
		Payload: &pb.EbpfEvent_Mount{ 
			Mount: &pb.MountEvent{
        DevName: unix.ByteSliceToString(raw.DevName[:]),
        DirName: unix.ByteSliceToString(raw.DirName[:]),
        Type: unix.ByteSliceToString(raw.Type[:]),
        Flags: raw.Flags,
			},
		},
	}

}
