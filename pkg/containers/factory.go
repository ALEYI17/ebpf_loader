package containers

import (
	"context"
	"ebpf_loader/pkg/containers/common"
	"ebpf_loader/pkg/containers/containerd"
	"ebpf_loader/pkg/logutil"
	"errors"
)


func NewRuntimeClient(ctx context.Context) (common.RuntimeClient,error){
  runtime := DetectRuntimeFromSystem() 
  logger := logutil.GetLogger()
  switch runtime.Runtime{
    case common.RuntimeContainerd:
      logger.Info("Creating containerd client")
      return containerd.NewContainerdClient(runtime, ctx) 
    case common.RuntimeCrio:
      logger.Info("Creating cri-o client ")
      return nil,errors.New("Unsuported or invalid runtime")
    case common.RuntimeDocker:
      logger.Info("Creating docker client")
      return nil,errors.New("Unsuported or invalid runtime")
    case common.RuntimePodman:
      logger.Info("Creating podman client")
      return nil,errors.New("Unsuported or invalid runtime")
    default:
      return nil,errors.New("Unsuported or invalid runtime")
  }
}
