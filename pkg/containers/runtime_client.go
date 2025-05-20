package containers

import (
	"context"

)

type RuntimeClient interface{
  ListContsiners(ctx context.Context) ([]ContainerInfo,error)
  GetContainerInfo(ctx context.Context,containerID string) (*ContainerInfo,error)
  Close()
}

type RuntimeDetection struct{
  Runtime string
  Socket string
  CgroupVersion string
}

const (
	RuntimeDocker     = "docker"
	RuntimeContainerd = "containerd"
	RuntimeCrio       = "crio"
	RuntimePodman     = "podman"
)

var runtimePriority = []string{
	RuntimeContainerd,
	RuntimeCrio,
  RuntimeDocker,
	RuntimePodman,
}

var RuntimeSockets = map[string][]string{
	RuntimeDocker: []string{
		"/var/run/docker.sock",
	},
	RuntimeContainerd: []string{
    "/run/k3s/containerd/containerd.sock",
		"/var/snap/microk8s/common/run/containerd.sock",
		"/run/k0s/containerd.sock",
		"/run/containerd/containerd.sock",
	},
	RuntimeCrio: []string{
		"/var/run/crio/crio.sock",
	},
	RuntimePodman: []string{
		"/run/podman/podman.sock",
	},
}

type ContainerInfo struct {
	ID     string
	Name   string
	Image  string
	PID    int
	Labels map[string]string
}
