package containerd

import (
	"context"
	"ebpf_loader/pkg/containers/common"
	"ebpf_loader/pkg/logutil"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"go.uber.org/zap"
)

type ContainerdClient struct{
  Client *containerd.Client
  Namespace context.Context
  NsName string 
}

func NewContainerdClient(runtime common.RuntimeDetection , ctx context.Context) (common.RuntimeClient,error){

  logger := logutil.GetLogger()

  client,err := containerd.New(runtime.Socket)

  if err != nil{
    return nil , err
  }

  ns , err:= selectNamespace(client,ctx)

  namespace := namespaces.WithNamespace(ctx, ns)

  logger.Info("The namespace is", zap.String("ns",ns ))
  return &ContainerdClient{Client: client,Namespace: namespace,NsName: ns},err
}

func (c *ContainerdClient) Close(){
  if c.Client != nil {
		_ = c.Client.Close()
	}
}

func selectNamespace(client *containerd.Client,ctx context.Context) (string,error){
  preferredOrder := []string{"k8s.io", "moby","docker", "default"}

  nsService := client.NamespaceService()

  namespaces , err := nsService.List(ctx)

  if err !=nil {
    return "default" , err
  }

  for _, ns := range preferredOrder {
    for _, available := range namespaces {
      if ns == available {
        return available,nil 
      }
    }
  }

  if len(namespaces) > 0 {
	  return namespaces[0],nil 
  }

  return "default" , nil
}


func (c *ContainerdClient) ListContainers(ctx context.Context) ([]common.ContainerInfo,error){
  
  containersList , err :=c.Client.Containers(c.Namespace)
  if err != nil {
    return nil, err
  }

  var containersInfo []common.ContainerInfo

  for _ , container := range containersList{

    info, err := container.Info(c.Namespace)

    if err != nil{
      continue
    }

    containersInfo =append(containersInfo,common.ContainerInfo{ID: info.ID,Image: info.Image, Labels: info.Labels})
  }
  
  return containersInfo,nil
} 

func (c *ContainerdClient) GetContainerInfo(ctx context.Context,containerID string) (*common.ContainerInfo,error){

  container , err := c.Client.LoadContainer(c.Namespace, containerID) 
  if err != nil {
    return nil , err
  }

  info,err := container.Info(c.Namespace)
  if err != nil {
    return nil , err
  }

  contInfo := &common.ContainerInfo{ID: info.ID,Image: info.Image,Labels: info.Labels}

  return contInfo,nil
}
