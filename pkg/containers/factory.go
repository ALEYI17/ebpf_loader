package containers

import (
	"context"
	"ebpf_loader/pkg/containers/common"
	"ebpf_loader/pkg/containers/containerd"
	"ebpf_loader/pkg/containers/docker"
	"ebpf_loader/pkg/containers/podman"
	"ebpf_loader/pkg/logutil"
	"errors"

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
      // not yet tested so i will put a continue 
      logger.Warn("Unsupported container runtime", zap.String("runtime", runtime.Runtime), zap.String("socket", runtime.Socket))
      continue
      //logger.Info("creating cri-o client", zap.String("socket", runtime.Socket))
      //c,err := crio.NewCrioClient(runtime, ctx)
      //if err !=nil{
      //  logger.Warn("Failed to create cri-o client", zap.Error(err))
      //  continue
      //}
      //result = append(result, c)
    case common.RuntimeDocker:
      logger.Info("Creating docker client", zap.String("socket", runtime.Socket))
      c,err :=docker.NewDockerClient() 
      if err != nil {
        logger.Warn("Failed to create docker client", zap.Error(err))
        continue
      }
      result = append(result, c)
    case common.RuntimePodman:
      logger.Info("Creating podman client", zap.String("socket", runtime.Socket))
      c,err := podman.NewPodmanClient(runtime, ctx)
      if err != nil {
        logger.Warn("Failed to create podman client", zap.Error(err))
        continue
      }
      result = append(result, c)
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


