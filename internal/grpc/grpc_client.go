package grpc

import (
	"context"
	"ebpf_loader/internal/grpc/pb"
	"ebpf_loader/pkg/logutil"
	"ebpf_loader/pkg/programs"
	"errors"
	"fmt"
	"io"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
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
  logger := logutil.GetLogger()

	stream, err := c.client.SendEvents(ctx)
	if err != nil {
		logger.Error("Error creating the stream", zap.Error(err))
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
				logger.Error("Error, cannot receive ack", zap.Error(err))
			}
			logger.Info("Ack message", zap.String("ack", ack.String()))
			logger.Info("Client received cancellation signal")
			return nil

		case event := <-eventCh:
			err := c.SendEventMessage(ctx, stream, event)
			if err != nil {
				logger.Error("Error from sending", zap.Error(err))

        status , ok := status.FromError(err)
        if ok && (status.Code()== codes.Unavailable || status.Code()== codes.Canceled){
          logger.Warn("Server unavailable. Shutting down client.")
          return err
        }

        if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled){
          logger.Warn("Stream closed. Shutting down client.")
          return err
        }
			}
			//logger.Info("Event sent successfully", zap.String("event", fmt.Sprintf("%v", event)))
		}
	}

}
