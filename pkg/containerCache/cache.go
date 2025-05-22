package containercache

import (
	"ebpf_loader/pkg/containers/common"
	"runtime"
	"sync"
	"time"
)

type CacheValue struct{
  info *common.ContainerInfo
  expiresAt time.Time
}

type Cache struct{
  data map[string] *CacheValue
  ttl time.Duration
  mu sync.RWMutex
  onEvicted  func(key string, info *common.ContainerInfo)
  janitor *Janitor
}

func NewCache(ttl time.Duration,ci time.Duration) *Cache{
  c:= &Cache{
    ttl: ttl,
    data: make(map[string]*CacheValue),
  }

  runJanitor(c, ci)
  runtime.SetFinalizer(c, stopJanitor)

  return c
}

func (c *Cache) Set(containerId string, info *common.ContainerInfo) {

  c.mu.Lock()
  defer c.mu.Unlock()

  c.data[containerId] = &CacheValue{info: info,expiresAt: time.Now().Add(c.ttl)}
}

func (c *Cache) Get(containerId string) (*common.ContainerInfo,bool){
  c.mu.RLock()
  defer c.mu.RUnlock()

  e, ok := c.data[containerId]

  if !ok || time.Now().After(e.expiresAt){
    return nil,false
  }

  remaining := time.Until(e.expiresAt)
	if remaining < c.ttl/3 {
		e.expiresAt = time.Now().Add(c.ttl)
	}

  return e.info,true
}

func (c *Cache) delete(key string) (*common.ContainerInfo, bool) {
	entry, found := c.data[key]
	if found {
		delete(c.data, key)
		return entry.info, true
	}
	return nil, false
}

func (c *Cache) evictExpired() {
	var evicted []struct {
		key  string
		info *common.ContainerInfo
	}

	c.mu.Lock()
	now := time.Now()
	for k, v := range c.data {
		if now.After(v.expiresAt) {
			info, ok := c.delete(k)
			if ok && c.onEvicted != nil {
				evicted = append(evicted, struct {
					key  string
					info *common.ContainerInfo
				}{k, info})
			}
		}
	}
	c.mu.Unlock()

	// Call onEvicted outside the lock
	for _, e := range evicted {
		c.onEvicted(e.key, e.info)
	}
}

func (c *Cache) OnEvicted(f func(string, *common.ContainerInfo)) {
	c.mu.Lock()
	c.onEvicted = f
	c.mu.Unlock()
}
