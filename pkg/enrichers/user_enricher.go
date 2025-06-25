package enrichers

import (
	"context"
	"ebpf_loader/internal/grpc/pb"
	"ebpf_loader/internal/metrics"
	"fmt"
	"os/user"
	"sync"
)

type UserEnricher struct{
  Users map[string]string 
  mu sync.RWMutex
}

func NewUserEnriche() *UserEnricher{
  return &UserEnricher{Users:make(map[string]string)}
}

func (e *UserEnricher) Enrich (ctx context.Context, event *pb.EbpfEvent) error{

  key := fmt.Sprintf("%d", event.Uid)

  e.mu.RLock()
  if user , ok := e.Users[key];ok{
    metrics.CacheHits.WithLabelValues("user enricher").Inc()
    e.mu.RUnlock()
    event.User = user
    return nil
  }
  e.mu.RUnlock()

  metrics.CacheMisses.WithLabelValues("user enricher").Inc()

  userInfo , err := user.LookupId(key)
	if err != nil {
    event.User = ""
    return err
	}

  e.mu.Lock()
  e.Users[key] = userInfo.Username
  e.mu.Unlock()
  event.User = userInfo.Username
  
  return nil
}

