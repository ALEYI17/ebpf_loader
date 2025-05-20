package containerd

import (
	"context"
	"ebpf_loader/pkg/containers"

	"github.com/containerd/containerd"
)

type ContainerdClient struct{
  client *containerd.Client
  namespace context.Context
}

func NewContainerdClient(runtime containers.RuntimeDetection) (*ContainerdClient,error){
  client,err := containerd.New("/run/containerd/containerd.sock")

  if err != nil{
    return nil , err
  }

  return &ContainerdClient{client: client},nil
}

func (c *ContainerdClient) Close(){
  c.Close()
}

func selectNamespace() (string,error){
}
func (c *ContainerdClient) ListContsiners(ctx context.Context) ([]containers.ContainerInfo,error){

} 
