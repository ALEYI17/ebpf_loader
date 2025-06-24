package podman

import (
	"context"
	"ebpf_loader/pkg/containers/common"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"time"
)

type podmanContainerInfoResponse struct {
	ID     string            `json:"id"`
	Image  string            `json:"image"`
	Labels map[string]string `json:"labels"`
}

type podmanInspectData struct{
  ID     string `json:"Id"`
		Image  string `json:"ImageName"` // sometimes it's ImageName instead of Image
		Config struct {
			Labels map[string]string `json:"Labels"`
      Annotations map[string]string `json:"Annotations"`
		} `json:"Config"`
}


type PodamnClient struct{
  Client *http.Client
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


func NewPodmanClient(runtime common.RuntimeDetection , ctx context.Context) (common.RuntimeClient,error){
  tr := new(http.Transport)

  if clientErr := configureUnixTransport(tr, "unix", runtime.Socket); clientErr != nil{
    return nil, clientErr
  }

  return &PodamnClient{Client: &http.Client{
    Transport: tr,
    Timeout: 1 * time.Second,
  }},nil
}


func (c *PodamnClient) Close(){
  if c.Client !=nil{
    c.Client.CloseIdleConnections()
  }
  return
}

func (c *PodamnClient) ListContainers(ctx context.Context) ([]common.ContainerInfo,error){
  var result []common.ContainerInfo

  req ,err := createRequest("/v4.0.0/libpod/containers/json?all=true")
  if err != nil {
    return nil, err
  }

  resp,err := c.Client.Do(req)
  if err != nil {
    return nil, err
  } 
  defer resp.Body.Close()
  if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("Error finding containers: Status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("Error finding containers: Status %d returned error %s", resp.StatusCode, string(respBody))
	}

  var contInfo []podmanContainerInfoResponse

  if err := json.NewDecoder(resp.Body).Decode(&contInfo); err !=nil{
    return nil,err
  }

  for _ ,ci := range contInfo{
    result = append(result, common.ContainerInfo{
      Image: ci.Image,
      ID: ci.ID,
      Labels: ci.Labels,
    })
  }

  return result,nil
}

func (c *PodamnClient) GetContainerInfo(ctx context.Context,containerID string) (*common.ContainerInfo,error){
  
  req,err := createRequest("/v4.0.0/libpod/containers/" + containerID + "/json")
  if err != nil {
    return nil, err
  }
  
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

  podmanInfo := podmanInspectData{}
  
  if err := json.NewDecoder(resp.Body).Decode(&podmanInfo);err !=nil{
    return nil, err
  }

  labels := make(map[string]string)
  maps.Copy(labels, podmanInfo.Config.Labels)
  maps.Copy(labels, podmanInfo.Config.Annotations)
  
  contInfo:= &common.ContainerInfo{
    Image: podmanInfo.Image,
    ID: podmanInfo.ID,
    Labels: labels,
  }

  return contInfo,nil
}


func createRequest(path string) (*http.Request,error){
  req, err := http.NewRequest("GET", "http://d"+path, nil)
  if err != nil {
    return nil, err
  }

  req.URL.Host = "d"
	req.URL.Scheme = "http"
  return req,nil
}
