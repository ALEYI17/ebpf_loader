package programs

import (
	"context"
	"ebpf_loader/internal/grpc/pb"
)

type Load_tracer interface{
  Close()
  Run(context.Context,string) <- chan *pb.EbpfEvent
}
