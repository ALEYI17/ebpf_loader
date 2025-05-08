package grpc

import (
	"context"
	"ebpf_loader/internal/grpc/pb"
	"ebpf_loader/pkg/programs"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	conn   *grpc.ClientConn
	client pb.EventCollectorClient
}

func NewClient(address string, port string) (*Client, error) {
  serverAdress := fmt.Sprintf("%s:%s", address,port)
	conn, err := grpc.NewClient(serverAdress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	client := pb.NewEventCollectorClient(conn)

	return &Client{conn: conn, client: client}, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) SendEventMessage(ctx context.Context, stream grpc.ClientStreamingClient[pb.EbpfEvent, pb.CollectorAck], batch *pb.EbpfEvent) error {

	err := stream.Send(batch)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) Run(ctx context.Context, loaders []programs.Load_tracer, nodeName string) error {

	stream, err := c.client.SendEvents(ctx)
	if err != nil {
		fmt.Printf("Error creating the stream %s", err)
		return err
	}

	eventCh := make(chan *pb.EbpfEvent, 500)

	for _, loader := range loaders {

		go func(l programs.Load_tracer) {
			tracerChannel := l.Run(ctx, nodeName)
			for {
				select {
				case <-ctx.Done():
					return
				case event := <-tracerChannel:
					eventCh <- event
				}
			}
		}(loader)
	}

	for {
		select {
		case <-ctx.Done():
			ack, err := stream.CloseAndRecv()
			if err != nil {
				fmt.Printf("Error , cannot receive ack %s", err)
			}
			fmt.Printf("Ack message: %s", ack)
			fmt.Printf("Client received cancellation signal")
			return nil

		case event := <-eventCh:
			err := c.SendEventMessage(ctx, stream, event)
			if err != nil {
				fmt.Printf("error from sending %s", err)
			}
			fmt.Println("Send info")
		}
	}

}
