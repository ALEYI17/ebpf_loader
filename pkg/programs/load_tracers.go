package programs

import (
	"context"
	"ebpf_loader/internal/grpc/pb"
)

type Load interface{
  Close() error
  Run(context.Context,string) <- chan pb.EbpfEvent
}
