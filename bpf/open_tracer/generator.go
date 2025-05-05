package opentracer

import (
	"ebpf_loader/internal/grpc/pb"
	"fmt"
	"os/user"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type trace_syscall_event  Opentracer open_tracer.bpf.c

// func GenerateGrpcMessage(raw OpentracerOpenEvent) pb.OpenEvent{
//   return pb.OpenEvent{
//     Pid:             raw.Pid,
// 		Uid:             raw.Uid,
//     Comm: unix.ByteSliceToString(raw.Comm[:]) ,
//     Filename: unix.ByteSliceToString(raw.Filename[:]),
//     Flags:           raw.Flags,
// 		ReturnCode:      raw.Ret,
// 		TimestampNs:     raw.TimestampNs,
// 		TimestampNsExit: raw.TimestampNsExit,
// 		LatencyNs:       raw.Latency,
//   }
// }

func GenerateGrpcMessage(raw OpentracerTraceSyscallEvent, nodeName string) *pb.EbpfEvent {
  username := ""

	userInfo, err := user.LookupId(fmt.Sprintf("%d", raw.Uid))

	if err == nil {
		username = userInfo.Username
	}

  return &pb.EbpfEvent{
		Pid:             raw.Pid,
		Uid:             raw.Uid,
		Comm:            unix.ByteSliceToString(raw.Comm[:]),
		Filename:        unix.ByteSliceToString(raw.Filename[:]),
		ReturnCode:      raw.Ret,
		TimestampNs:     raw.TimestampNs,
		TimestampNsExit: raw.TimestampNsExit,
		LatencyNs:       raw.Latency,
		EventType:       "open",
		NodeName:        nodeName,
    User: username,
    Ppid: 0,
	}}
