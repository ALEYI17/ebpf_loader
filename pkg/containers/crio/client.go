package crio

import (
	"context"
	containercache "ebpf_loader/pkg/containerCache"
	"ebpf_loader/pkg/containers/common"
	"ebpf_loader/pkg/logutil"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"
)


type CrioClient struct{
  Client *http.Client
  Cache *containercache.Cache
}

type crioContainerInfoResponse struct {
	ID     string            `json:"id"`
	Image  string            `json:"image"`
	Labels map[string]string `json:"labels"`
}

func configureUnixTransport(tr *http.Transport, proto, addr string) error{

  if len(addr) > common.MaxUnixSocketPathSize{
    return errors.New(fmt.Sprintf("unix socket path %s is too long", addr))
  }

  tr.DisableCompression = true
  tr.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.DialTimeout(proto, addr, 32*time.Second)
	}

  return nil
}

func NewCrioClient(runtime common.RuntimeDetection,ctx context.Context) (common.RuntimeClient,error){
  logger := logutil.GetLogger()
  
  tr := new(http.Transport)

  if clientErr := configureUnixTransport(tr, "unix", runtime.Socket); clientErr != nil{
    logger.Warn("Error creating crio client", zap.Error(clientErr))
    return nil, clientErr
  }

  return &CrioClient{
    Client: &http.Client{
      Transport: tr,
      Timeout: 1 * time.Second,
    },
  },nil

}

func NewcrioClientWithCache(runtime common.RuntimeDetection , ctx context.Context,ttl ,ci time.Duration) (common.RuntimeClient,error){

  logger := logutil.GetLogger()
  
  tr := new(http.Transport)

  if clientErr := configureUnixTransport(tr, "unix", runtime.Socket); clientErr != nil{
    logger.Warn("Error creating crio client", zap.Error(clientErr))
    return nil, clientErr
  }

  cache := containercache.NewCache(ttl, ci)

  return &CrioClient{
    Client: &http.Client{
      Transport: tr,
      Timeout: 1 * time.Second,
    },
    Cache: cache,
  },nil

}


func (c *CrioClient) Close(){
  if c.Client !=nil{
    c.Client.CloseIdleConnections()
  }
  return 
}


func (c * CrioClient) ListContainers(ctx context.Context) ([]common.ContainerInfo,error){
  return nil, fmt.Errorf("ListContainers is not supported in the CRI-O HTTP API")
}


func (c *CrioClient) GetContainerInfo(ctx context.Context,containerID string) (*common.ContainerInfo,error){

  if c.Cache != nil{
    if info,ok := c.Cache.Get(containerID);ok{
      return info,nil
    }
  }
  req,err := createRequest("/containers/" + containerID)

  if err != nil {
    return nil, err
  }

  crioInfo := crioContainerInfoResponse{}
  resp,err := c.Client.Do(req)
  if err != nil {
    return nil, err
  }

  defer resp.Body.Close()

  if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("Error finding container %s: Status %d", containerID, resp.StatusCode)
		}
		return nil, fmt.Errorf("Error finding container %s: Status %d returned error %s", containerID, resp.StatusCode, string(respBody))
	}

  if err := json.NewDecoder(resp.Body).Decode(&crioInfo); err !=nil{
    return nil , err
  }
  
  contInfo:= &common.ContainerInfo{
    ID: crioInfo.ID,
    Image: crioInfo.Image,
    Labels: crioInfo.Labels,
  }

  if c.Cache != nil {
    c.Cache.Set(containerID, contInfo)
  }
  return contInfo,nil
}


func createRequest(path string) (*http.Request,error){
  req, err := http.NewRequest("GET", path, nil)
  if err != nil {
    return nil, err
  }

  req.Host = "crio"
  req.URL.Host = "/var/run/crio/crio.sock"
  req.URL.Scheme = "http"
  return req,nil
}
