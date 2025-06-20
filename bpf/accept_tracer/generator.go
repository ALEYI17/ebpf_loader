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
  var (
		saddrv4, daddrv4 string
		saddrv6, daddrv6 string
	)

	switch raw.SaFamily {
	case 2: // AF_INET
		saddrv4 = uint32ToIPv4(raw.SaddrV4)
		daddrv4 = uint32ToIPv4(raw.DaddrV4)
		saddrv6 = ""
		daddrv6 = ""

	case 10: // AF_INET6
		ip6src := net.IP(raw.SaddrV6[:])
		ip6dst := net.IP(raw.DaddrV6[:])

		// Check if IPv4-mapped
		if ip4src := ip6src.To4(); ip4src != nil {
			saddrv4 = ip4src.String()
		}
		if ip4dst := ip6dst.To4(); ip4dst != nil {
			daddrv4 = ip4dst.String()
		}

		// If not mapped IPv4, keep original IPv6
		if saddrv4 == "" {
			saddrv6 = ip6src.String()
		}
		if daddrv4 == "" {
			daddrv6 = ip6dst.String()
		}

	default:
		saddrv4, daddrv4 = "", ""
		saddrv6, daddrv6 = "", ""
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
		TimestampNs:     raw.TimestampNsEnter,
		TimestampNsExit: raw.TimestampNsExit,
		LatencyNs:       raw.LatencyNs,
		EventType:       "accept",
		NodeName:        nodeName,
		TimestampUnixMs: time.Now().UnixMilli(),
		Payload: &pb.EbpfEvent_Network{ // oneof for NetworkEvent
			Network: &pb.NetworkEvent{
				ReturnCode: raw.Ret,
				Saddrv4:      saddrv4,
				Daddrv4:      daddrv4,
				Sport:      strconv.Itoa(int(raw.Sport)),
				Dport:      strconv.Itoa(int(raw.Dport)),
				SaFamily:   saFamilyToString(raw.SaFamily),
        Saddrv6: saddrv6,
        Daddrv6: daddrv6,
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
