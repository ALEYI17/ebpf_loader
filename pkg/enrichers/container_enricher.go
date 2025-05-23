package enrichers

import (
	"context"
	"ebpf_loader/internal/grpc/pb"
	"ebpf_loader/pkg/containers/common"
	"ebpf_loader/pkg/logutil"
	"encoding/json"
	"errors"
	"regexp"

	"go.uber.org/zap"
)

type ContainerEnricher struct{
  common.RuntimeClient
}

var dockerIDRegex = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

func NewContainerenricher(client common.RuntimeClient) *ContainerEnricher{
  return &ContainerEnricher{RuntimeClient: client}
}

func (e *ContainerEnricher) Enrich (ctx context.Context, event *pb.EbpfEvent) error{

  logger := logutil.GetLogger()

  if event.CgroupName == "" {
		event.ContainerId = ""
		event.ContainerImage = ""
    event.ContainerLabelsJson = ""
		return nil // Not an error!
	}

	containerID, err := extractContainerID(event.CgroupName)
	if err != nil {
		event.ContainerId = ""
		event.ContainerImage = ""
    event.ContainerLabelsJson = ""
		return nil // Still not an error — just not containerized
	}

  containerInfo,err:=e.GetContainerInfo(ctx, containerID)
  if err != nil {
    return err
  }

  event.ContainerId = containerInfo.ID
  event.ContainerImage = containerInfo.Image
  data ,err := json.Marshal(containerInfo.Labels); 
  if err != nil{
    event.ContainerLabelsJson = ""
    logger.Warn("Could not marshall labels", zap.Error(err))
    return err
  }
  event.ContainerLabelsJson = string(data)
  return nil
}

func extractContainerID(cgroupName string) (string, error) {
	if dockerIDRegex.MatchString(cgroupName) {
		return cgroupName, nil
	}
	return "", errors.New("not a valid Docker container ID")
}
