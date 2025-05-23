package docker

import (
	"context"
	"ebpf_loader/pkg/containerCache"
	"ebpf_loader/pkg/containers/common"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
) 

type DockerClient struct{
  client *client.Client
  cache *containercache.Cache
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

func NewDockerClientWithCache(ttl,ci time.Duration) (common.RuntimeClient,error){

  client, err := client.NewClientWithOpts(client.FromEnv,client.WithAPIVersionNegotiation())

  if err != nil {
    return nil, err
  }

  cache := containercache.NewCache(ttl, ci)
  return &DockerClient{client: client,cache: cache},nil
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

  if c.cache != nil{
    if info , ok := c.cache.Get(containerID); ok {
      return info, nil
    } 

  }
  inspect,err:= c. client.ContainerInspect(ctx, containerID)
  if err != nil {
    return nil, err
  }

  info := &common.ContainerInfo{ID: inspect.ID,Image: inspect.Config.Image,Labels: inspect.Config.Labels}

  if c.cache != nil {
    c.cache.Set(containerID, info)
  }
  return info ,nil
}
