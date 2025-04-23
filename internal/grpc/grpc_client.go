package grpc

import (
	"context"
	"ebpf_loader/internal/grpc/pb"
	"time"

	"google.golang.org/grpc"
)

type Client struct{
  conn *grpc.ClientConn
  client pb.EventCollectorClient
}

func NewClient(address string) (*Client, error){

  conn, err := grpc.NewClient(address)
  if err != nil {
    return nil,err
  }

  defer conn.Close()

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

func (c *Client) Run() error{
  return nil
} 
