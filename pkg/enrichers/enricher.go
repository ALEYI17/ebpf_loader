package enrichers

import (
	"context"
	"ebpf_loader/internal/grpc/pb"
)

type Enricher interface{
  Enrich (ctx context.Context, event *pb.EbpfEvent) error
}
