package containerd

import (
	"context"
	"ebpf_loader/pkg/containers"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
)

type ContainerdClient struct{
  Client *containerd.Client
  Namespace context.Context
  NsName string
}

func NewContainerdClient(runtime containers.RuntimeDetection , ctx context.Context) (*ContainerdClient,error){

  client,err := containerd.New(runtime.Socket)

  if err != nil{
    return nil , err
  }

  ns , err:= selectNamespace(client,ctx)

  namespace := namespaces.WithNamespace(ctx, ns)

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


func (c *ContainerdClient) ListContainers(ctx context.Context) ([]containers.ContainerInfo,error){
  
  containersList , err :=c.Client.Containers(c.Namespace)
  if err != nil {
    return nil, err
  }

  var containersInfo []containers.ContainerInfo

  for _ , container := range containersList{

    info, err := container.Info(ctx)

    if err != nil{
      continue
    }

    containersInfo =append(containersInfo,containers.ContainerInfo{ID: info.ID,Image: info.Image, Labels: info.Labels})
  }
  
  return containersInfo,nil
} 
