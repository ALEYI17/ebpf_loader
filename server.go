package main

import (
	"io"
	"log"
	"net"

	"google.golang.org/grpc"

	pb "ebpf_loader/internal/grpc/pb"
)

type server struct {
	pb.UnimplementedEventCollectorServer
}

func (s *server) SendEvents(stream pb.EventCollector_SendEventsServer) error {
	log.Println("📡 Receiving streamed events...")

	for {
		event, err := stream.Recv()
		if err == io.EOF {
			// Client has closed the stream
			log.Println("✅ Finished receiving all events.")
			return stream.SendAndClose(&pb.CollectorAck{
				Status:  "OK",
				Message: "All events received successfully",
			})
		}
		if err != nil {
			log.Printf("❌ Error receiving event: %v", err)
			return err
		}

		log.Println("🛰️ Event from node:", event.GetNodeName())

		switch ev := event.GetEvent().(type) {
		case *pb.EbpfEvent_OpenEvent:
			log.Printf("📂 OpenEvent: PID=%d UID=%d COMM=%s FILENAME=%s FLAGS=%d RET=%d TS=%d EXIT_TS=%d LAT=%d\n",
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
			log.Printf("📦 ExecveEvent: PID=%d UID=%d COMM=%s FILENAME=%s RET=%d TS=%d EXIT_TS=%d LAT=%d\n",
				ev.ExecveEvent.Pid,
				ev.ExecveEvent.Uid,
				ev.ExecveEvent.Comm,
				ev.ExecveEvent.Filename,
				ev.ExecveEvent.ReturnCode,
				ev.ExecveEvent.TimestampNs,
				ev.ExecveEvent.TimestampNsExit,
				ev.ExecveEvent.LatencyNs,
			)
		default:
			log.Println("🚨 Unknown event type received")
		}
	}
}

func main() {
	log.Println("🚀 Starting gRPC server on :8080...")

	lis, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterEventCollectorServer(grpcServer, &server{})

	log.Println("✅ Server ready and listening")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
