package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"

	pb "ebpf_loader/internal/grpc/pb"
)

type server struct {
	pb.UnimplementedEventCollectorServer
}

func (s *server) SendEvents(ctx context.Context, event *pb.EbpfEvent) (*pb.CollectorAck, error) {
	log.Println("📦 Received event from node:", event.GetNodeName())

	switch ev := event.GetEvent().(type) {
	case *pb.EbpfEvent_OpenEvent:
		log.Printf("🔓 OpenEvent: PID=%d UID=%d COMM=%s FILENAME=%s FLAGS=%d RET=%d TS=%d EXIT_TS=%d LAT=%d\n",
			ev.OpenEvent.Pid,
			ev.OpenEvent.Uid,
			ev.OpenEvent.Comm,
			ev.OpenEvent.Filename,
			ev.OpenEvent.Flags,
			ev.OpenEvent.ReturnCode,
			ev.OpenEvent.TimestampNs,
			ev.OpenEvent.TimestampNsExit,
			ev.OpenEvent.LatencyNs,
		)

	case *pb.EbpfEvent_ExecveEvent:
		log.Printf("🚀 ExecveEvent: PID=%d UID=%d COMM=%s FILENAME=%s ARGV=%v RET=%d TS=%d LAT=%d\n",
			ev.ExecveEvent.Pid,
			ev.ExecveEvent.Uid,
			ev.ExecveEvent.Comm,
			ev.ExecveEvent.Filename,
			ev.ExecveEvent.Argv,
			ev.ExecveEvent.ReturnCode,
			ev.ExecveEvent.TimestampNs,
			ev.ExecveEvent.LatencyNs,
		)

	default:
		log.Println("⚠️ Unknown event type")
	}

	return &pb.CollectorAck{
		Status:  "OK",
		Message: "Event received successfully",
	}, nil
}
func main() {
	log.Println("Starting server...")

	lis, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterEventCollectorServer(grpcServer, &server{})

	log.Println("Server ready on :8080")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

