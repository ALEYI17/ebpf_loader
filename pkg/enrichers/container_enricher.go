package enrichers

import (
	"context"
	"ebpf_loader/internal/grpc/pb"
	"ebpf_loader/pkg/containers/common"
	"errors"
	"regexp"
)

type ContainerEnricher struct{
  common.RuntimeClient
}

var dockerIDRegex = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

func NewContainerenricher(client common.RuntimeClient) *ContainerEnricher{
  return &ContainerEnricher{RuntimeClient: client}
}

func (e *ContainerEnricher) Enrich (ctx context.Context, event *pb.EbpfEvent) error{

  if event.CgroupName == "" {
		event.ContainerId = ""
		event.ContainerImage = ""
		return nil // Not an error!
	}

	containerID, err := extractContainerID(event.CgroupName)
	if err != nil {
		event.ContainerId = ""
		event.ContainerImage = ""
		return nil // Still not an error — just not containerized
	}

  containerInfo,err:=e.GetContainerInfo(ctx, containerID)
  if err != nil {
    return err
  }

  event.ContainerId = containerInfo.ID
  event.ContainerImage = containerInfo.Image

  return nil
}

func extractContainerID(cgroupName string) (string, error) {
	if dockerIDRegex.MatchString(cgroupName) {
		return cgroupName, nil
	}
	return "", errors.New("not a valid Docker container ID")
}
