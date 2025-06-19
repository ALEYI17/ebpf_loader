package enrichers

import (
	"context"
	"ebpf_loader/internal/grpc/pb"
	"ebpf_loader/pkg/containers/common"
	"fmt"
	"regexp"
	"strings"
)

type ContainerEnricher struct{
  RuntimeClients []common.RuntimeClient
}

var (
	dockerIDRegex         = regexp.MustCompile(`^[a-f0-9]{12,64}$`)
	cgroupScopeRegex      = regexp.MustCompile(`(?i)(docker|cri-containerd|crio|cri-o|podman|libpod)[-:]([a-f0-9]{12,64})(?:\.scope)?`)
	systemdScopeRegex     = regexp.MustCompile(`([a-f0-9]{12,64})\.scope`)
)
func NewContainerenricher(client []common.RuntimeClient) *ContainerEnricher{
  return &ContainerEnricher{RuntimeClients: client}
}

func (e *ContainerEnricher) Enrich (ctx context.Context, event *pb.EbpfEvent) error{

  if event.CgroupName == "" {
		event.ContainerId = ""
		event.ContainerImage = ""
    event.ContainerLabelsJson = nil
		return nil // Not an error!
	}

	containerID, err := extractContainerID(event.CgroupName)
	if err != nil {
		event.ContainerId = ""
		event.ContainerImage = ""
    event.ContainerLabelsJson = nil
		return nil // Still not an error — just not containerized
	}

  containerInfo,err:=e.GetContainerInfo(ctx, containerID)
  if err != nil {
    return err
  }

  event.ContainerId = containerInfo.ID
  event.ContainerImage = containerInfo.Image
  event.ContainerLabelsJson = containerInfo.Labels
  return nil
}

func extractContainerID(cgroupName string) (string, error) {
	// cgroup v1 style — the ID is the full string
	if dockerIDRegex.MatchString(cgroupName) {
		return cgroupName, nil
	}

	// Match common cgroup v2 scope formats
	if matches := cgroupScopeRegex.FindStringSubmatch(cgroupName); len(matches) == 3 {
		return matches[2], nil // ID is the 2nd capturing group
	}

	// Match systemd-style IDs like abc123.scope (fallback)
	if matches := systemdScopeRegex.FindStringSubmatch(cgroupName); len(matches) == 2 {
		return matches[1], nil
	}

	return "", fmt.Errorf("could not extract container ID from cgroup name: %s", cgroupName)
}

func (e *ContainerEnricher) GetContainerInfo(ctx context.Context, containerID string) (*common.ContainerInfo,error){

  var errorList []string

  for _,client := range e.RuntimeClients{
    info,err := client.GetContainerInfo(ctx, containerID)
    if err ==nil && info!=nil{
      return info,nil
    }
    if err !=nil{
      errorList = append(errorList, err.Error())
    }

  }

  return nil, fmt.Errorf("container %s not found in any runtime. Errors: [%s]", containerID, strings.Join(errorList, "; "))
}
