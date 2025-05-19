package containers

import "context"

type RuntimeClient interface{
  ListContsiners(ctx context.Context) ([]ContainerInfo,error)
  GetContainerInfo(ctx context.Context,containerID string) (*ContainerInfo,error)
  Close()
}

type ContainerInfo struct {
	ID     string
	Name   string
	Image  string
	PID    int
	Labels map[string]string
}
