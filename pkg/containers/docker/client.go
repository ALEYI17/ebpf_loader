package docker

import (
	"context"
	"ebpf_loader/pkg/containers/common"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
) 

type DockerClient struct{
  client *client.Client
}

func NewDockerClient() (common.RuntimeClient,error){

  client, err := client.NewClientWithOpts(client.FromEnv,client.WithAPIVersionNegotiation())

  if err != nil {
    return nil, err
  }

  return &DockerClient{client: client},nil
}

func (c *DockerClient) Close(){
  if c.client !=nil{
    c.client.Close()
  }
}

func (c *DockerClient) ListContainers(ctx context.Context) ([]common.ContainerInfo,error){
  
  var result []common.ContainerInfo

  containersList , err := c.client.ContainerList(ctx, container.ListOptions{All:true})

  if err != nil {
    return nil , err
  }

  for _ , contain := range containersList{
    result = append(result, common.ContainerInfo{Image: contain.Image,ID: contain.ID,Labels: contain.Labels})
  }

  return result,nil
}

func (c *DockerClient) GetContainerInfo(ctx context.Context,containerID string) (*common.ContainerInfo,error) {

  inspect,err:= c. client.ContainerInspect(ctx, containerID)
  if err != nil {
    return nil, err
  }

  return &common.ContainerInfo{ID: inspect.ID,Image: inspect.Config.Image,Labels: inspect.Config.Labels},nil
}
