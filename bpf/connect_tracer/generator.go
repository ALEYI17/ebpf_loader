package connecttracer

import (
	"ebpf_loader/internal/grpc/pb"
	"encoding/binary"
	"net"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type socket_event_t   Connecttracer connect_tracer.bpf.c


func GenerateGrpcMessage(raw ConnecttracerSocketEventT, nodeName string) *pb.EbpfEvent {
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
		TimestampNs:     raw.TimestampNsEnter,
		TimestampNsExit: raw.TimestampNsExit,
		LatencyNs:       raw.LatencyNs,
		EventType:       "connect",
		NodeName:        nodeName,
		TimestampUnixMs: time.Now().UnixMilli(),
		Payload: &pb.EbpfEvent_Network{ // oneof for NetworkEvent
			Network: &pb.NetworkEvent{
				ReturnCode: raw.Ret,
				Saddr:      uint32ToIPv4(raw.Saddr),
				Daddr:      uint32ToIPv4(raw.Daddr),
				Sport:      strconv.Itoa(int(raw.Sport)),
				Dport:      strconv.Itoa(int(raw.Dport)),
				SaFamily:   saFamilyToString(raw.SaFamily),
			},
		},
	}
}
func uint32ToIPv4(ipUint32 uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipUint32)
	return ip.String()
}

func saFamilyToString(family uint16) string {
	switch family {
	case 2:
		return "AF_INET"
	case 10:
		return "AF_INET6"
	default:
		return "UNKNOWN"
	}
}
