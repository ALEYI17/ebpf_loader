package containers

import (
	"context"
	"ebpf_loader/pkg/containers/common"
	"ebpf_loader/pkg/containers/containerd"
	"ebpf_loader/pkg/containers/docker"
	"ebpf_loader/pkg/logutil"
	"errors"
	"time"

	"go.uber.org/zap"
)


func NewRuntimeClient(ctx context.Context) ([]common.RuntimeClient,error){
  runtimes := DetectRuntimeFromSystem() 
  logger := logutil.GetLogger()
  var result []common.RuntimeClient
  for _,runtime := range runtimes{
    switch runtime.Runtime{
    case common.RuntimeContainerd:
      logger.Info("Creating containerd client", zap.String("socket", runtime.Socket))
      c ,err := containerd.NewContainerdClient(runtime, ctx) 
      if err != nil{
        logger.Warn("Failed to create containerd client", zap.Error(err))
        continue
      }
      result = append(result, c)
    case common.RuntimeCrio:
      logger.Warn("Unsupported container runtime", zap.String("runtime", runtime.Runtime), zap.String("socket", runtime.Socket))
      continue
    case common.RuntimeDocker:
      logger.Info("Creating docker client", zap.String("socket", runtime.Socket))
      c,err :=docker.NewDockerClient() 
      if err != nil {
        logger.Warn("Failed to create docker client", zap.Error(err))
        continue
      }
      result = append(result, c)
    case common.RuntimePodman:
      logger.Warn("Unsupported container runtime", zap.String("runtime", runtime.Runtime), zap.String("socket", runtime.Socket))
      continue
    default:
      logger.Warn("Unknown container runtime", zap.String("runtime", runtime.Runtime))
      continue
    }

  }

  if len(result)==0{
    return nil, errors.New("no valid container runtimes could be initialized")
  }
  return result,nil
}

func NewRuntimeClientWithCache(ctx context.Context,ttl , ci time.Duration) ([]common.RuntimeClient,error){
  runtimes := DetectRuntimeFromSystem() 
  logger := logutil.GetLogger()
  var result []common.RuntimeClient
  for _,runtime := range runtimes{
    switch runtime.Runtime{
    case common.RuntimeContainerd:
      logger.Info("Creating containerd client", zap.String("socket", runtime.Socket))
      c,err :=containerd.NewContainerdClientWithCache(runtime, ctx,ttl,ci) 
      if err !=nil{
        logger.Warn("Failed to create containerd client", zap.Error(err))
        continue
      }
      result = append(result, c)
    case common.RuntimeCrio:
      logger.Warn("Unsupported container runtime", zap.String("runtime", runtime.Runtime), zap.String("socket", runtime.Socket))
      continue
    case common.RuntimeDocker:
      logger.Info("Creating docker client", zap.String("socket", runtime.Socket))
      c,err := docker.NewDockerClientWithCache(ttl, ci) 
      if err != nil {
        logger.Warn("Failed to create docker client", zap.Error(err))
        continue
      }
      result = append(result, c)
    case common.RuntimePodman:
      logger.Warn("Unsupported container runtime", zap.String("runtime", runtime.Runtime), zap.String("socket", runtime.Socket))
      continue
    default:
      logger.Warn("Unknown container runtime", zap.String("runtime", runtime.Runtime))
      continue
    }
  } 
  
  if len(result)==0{
    return nil, errors.New("no valid container runtimes could be initialized")
  }

  return result,nil
}
