package umounttracer

import (
	"ebpf_loader/internal/grpc/pb"
	"time"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type mount_event_t Umounttracer umount_tracer.bpf.c

func GenerateGrpcMessage(raw UmounttracerMountEventT, nodeName string) *pb.EbpfEvent{
  
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
		EventType:       "umount",
		NodeName:        nodeName,
		TimestampUnixMs: time.Now().UnixMilli(),
		Payload: &pb.EbpfEvent_Mount{ 
			Mount: &pb.MountEvent{
        DevName: "",
        DirName: unix.ByteSliceToString(raw.DirName[:]),
        Type: "",
        Flags: raw.Flags,
        ReturnCode: raw.Ret,
			},
		},
	}

}
