package connecttracer

import "ebpf_loader/internal/grpc/pb"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type socket_event_t   Connecttracer connect_tracer.bpf.c


func GenerateGrpcMessage(raw ConnecttracerSocketEventT, nodeName string) *pb.EbpfEvent
