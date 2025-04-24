package grpc

import (
	"context"
	"ebpf_loader/internal/grpc/pb"
	"ebpf_loader/pkg/programs"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct{
  conn *grpc.ClientConn
  client pb.EventCollectorClient
}

func NewClient(address string) (*Client, error){

  conn, err := grpc.NewClient(address,grpc.WithTransportCredentials(insecure.NewCredentials()))
  if err != nil {
    return nil,err
  }

  client := pb.NewEventCollectorClient(conn)

  return &Client{conn: conn,client: client},nil
}

func (c *Client) Close() error{
  return c.conn.Close()
}

func (c *Client) SendEventMessage(ctx context.Context,stream grpc.ClientStreamingClient[pb.EbpfEvent,pb.CollectorAck] , batch *pb.EbpfEvent)error{

  err := stream.Send(batch)
  if err != nil {
    return err
  }
  
  return nil
}

func (c *Client) Run(ctx context.Context, loader programs.Load_tracer,nodeName string) error{

  stream,err := c.client.SendEvents(ctx)
  if err != nil{
    fmt.Printf("Error creating the stream %s", err)
    return err
  }

  openLoader:= loader.Run(ctx, nodeName)
  
  for{
    select{
      case <- ctx.Done():
        ack,err := stream.CloseAndRecv()
        if err != nil{
          fmt.Printf("Error , cannot receive ack %s", err)
        }
      fmt.Printf("Ack message: %s", ack)
        fmt.Printf("Client received cancellation signal")
        return nil

    case event:= <- openLoader:
      err:= c.SendEventMessage(ctx,stream ,event)
      if err !=nil{
        fmt.Printf("error from sending %s", err)
      }
      fmt.Println("Send info")
    }
  }
  
} 
