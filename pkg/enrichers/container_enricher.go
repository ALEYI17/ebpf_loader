package enrichers

import (
	"context"
	"ebpf_loader/internal/grpc/pb"
	"ebpf_loader/pkg/containers/common"
)

type ContainerEnricher struct{
  common.RuntimeClient
}

func NewContainerenricher(client common.RuntimeClient) *ContainerEnricher{
  return &ContainerEnricher{RuntimeClient: client}
}

func (e *ContainerEnricher) Enrich (ctx context.Context, event *pb.EbpfEvent) error{
  return nil
}
