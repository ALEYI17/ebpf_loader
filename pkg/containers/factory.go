package containers

import (
	"ebpf_loader/pkg/logutil"
	"errors"

)


func NewRuntimeClient(runtime string) (*RuntimeClient,error){
  logger := logutil.GetLogger()
  switch runtime{
    case RuntimeContainerd:
      logger.Info("Creating containerd client")
      return nil,errors.New("Unsuported or invalid runtime")
    case RuntimeCrio:
      logger.Info("Creating cri-o client ")
      return nil,errors.New("Unsuported or invalid runtime")
    case RuntimeDocker:
      logger.Info("Creating docker client")
      return nil,errors.New("Unsuported or invalid runtime")
    case RuntimePodman:
      logger.Info("Creating podman client")
      return nil,errors.New("Unsuported or invalid runtime")
    default:
      return nil,errors.New("Unsuported or invalid runtime")
  }
}
