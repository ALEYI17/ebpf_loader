package accepttracer
import (
	"ebpf_loader/internal/grpc/pb"
	"encoding/binary"
	"net"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type socket_event_t Accepttracer accept_tracer.bpf.c

func GenerateGrpcMessage(raw AccepttracerSocketEventT, nodeName string) *pb.EbpfEvent {
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
				Saddrv4:      uint32ToIPv4(raw.SaddrV4),
				Daddrv4:      uint32ToIPv4(raw.DaddrV4),
				Sport:      strconv.Itoa(int(raw.Sport)),
				Dport:      strconv.Itoa(int(raw.Dport)),
				SaFamily:   saFamilyToString(raw.SaFamily),
        Saddrv6: uint8ToIpv6(raw.SaddrV6),
        Daddrv6: uint8ToIpv6(raw.DaddrV6),
			},
		},
	}
}
func uint32ToIPv4(ipUint32 uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipUint32)
	return ip.String()
}

func uint8ToIpv6 (ipUint8 [16]uint8) string{
  ip := net.IP(ipUint8[:])  
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
