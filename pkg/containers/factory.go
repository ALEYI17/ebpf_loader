package containers

import (
	"context"
	"ebpf_loader/pkg/containers/common"
	"ebpf_loader/pkg/containers/containerd"
	"ebpf_loader/pkg/containers/docker"
	"ebpf_loader/pkg/logutil"
	"errors"
	"time"
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
      return docker.NewDockerClient() 
    case common.RuntimePodman:
      logger.Info("Creating podman client")
      return nil,errors.New("Unsuported or invalid runtime")
    default:
      return nil,errors.New("Unsuported or invalid runtime")
  }
}

func NewRuntimeClientWithCache(ctx context.Context,ttl , ci time.Duration) (common.RuntimeClient,error){
  runtime := DetectRuntimeFromSystem() 
  logger := logutil.GetLogger()
  switch runtime.Runtime{
    case common.RuntimeContainerd:
      logger.Info("Creating containerd client")
      return containerd.NewContainerdClientWithCache(runtime, ctx,ttl,ci) 
    case common.RuntimeCrio:
      logger.Info("Creating cri-o client ")
      return nil,errors.New("Unsuported or invalid runtime")
    case common.RuntimeDocker:
      logger.Info("Creating docker client")
      return docker.NewDockerClientWithCache(ttl, ci) 
    case common.RuntimePodman:
      logger.Info("Creating podman client")
      return nil,errors.New("Unsuported or invalid runtime")
    default:
      return nil,errors.New("Unsuported or invalid runtime")
  }
}
