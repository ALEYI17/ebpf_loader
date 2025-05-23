package enrichers

import (
	"context"
	"ebpf_loader/internal/grpc/pb"
	"ebpf_loader/pkg/logutil"

	"go.uber.org/zap"
)

type MultiEnricher struct{
  enrichers []Enricher
}

func NewMultiEnricher (enrichers ... Enricher) *MultiEnricher{
  return &MultiEnricher{enrichers: enrichers}
}

func (e *MultiEnricher) Enrich (ctx context.Context, event *pb.EbpfEvent) error{

  logger := logutil.GetLogger()
  for _, enricher := range e.enrichers{
    if err := enricher.Enrich(ctx, event); err !=nil{
      logger.Warn("Error in enricher", zap.Error(err))
    }
  }

  return nil
} 
