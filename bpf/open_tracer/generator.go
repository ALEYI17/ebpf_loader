package opentracer

import (
	"ebpf_loader/internal/grpc/pb"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type Open_event Opentracer open_tracer.bpf.c

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

func GenerateGrpcMessage(raw OpentracerOpenEvent, nodeName string) *pb.EbpfEvent {
	return &pb.EbpfEvent{
		Event: &pb.EbpfEvent_OpenEvent{
			OpenEvent: &pb.OpenEvent{
				Pid:             raw.Pid,
				Uid:             raw.Uid,
				Comm:            unix.ByteSliceToString(raw.Comm[:]),
				Filename:        unix.ByteSliceToString(raw.Filename[:]),
				Flags:           raw.Flags,
				ReturnCode:      raw.Ret,
				TimestampNs:     raw.TimestampNs,
				TimestampNsExit: raw.TimestampNsExit,
				LatencyNs:       raw.Latency,
			},
		},
		NodeName: nodeName,
	}
}
