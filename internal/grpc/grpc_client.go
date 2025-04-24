package grpc

import (
	"context"
	"ebpf_loader/internal/grpc/pb"
	"ebpf_loader/pkg/programs"
	"fmt"
	"time"

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

func (c *Client) SendEventMessage(ctx context.Context, batch *pb.EbpfEvent) (*pb.CollectorAck,error){

  ctx, cancel := context.WithTimeout(ctx, time.Second*5)
  defer cancel()

  resp, err := c.client.SendEvents(ctx, batch)
  if err != nil {
    return nil,err
  }

  return resp,nil
}

func (c *Client) Run(ctx context.Context, loader programs.Load_tracer,nodeName string) error{
  openLoader:= loader.Run(ctx, nodeName)
  
  for{
    select{
      case <- ctx.Done():
        fmt.Printf("Client received cancellation signal")
        return nil

    case event:= <- openLoader:
      ack , err:= c.SendEventMessage(ctx, event)
      if err !=nil{
        fmt.Printf("error from sending %s", err)
      }
      fmt.Printf("Ack:%s", ack)
      fmt.Println("Send info")
    }
  }
} 
