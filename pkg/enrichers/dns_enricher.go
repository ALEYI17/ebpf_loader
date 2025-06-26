package enrichers

import (
	"context"
	"ebpf_loader/internal/grpc/pb"
	"errors"
	"net"
	"sync"
	"time"
)

type DnsEnricher struct{
  DnsAddrs map[string]string
  mu sync.RWMutex
  privateIPNets []*net.IPNet
}


func NewDnsenricher() *DnsEnricher{
  privateCIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16", // link-local (optional)
		"127.0.0.0/8",    // loopback
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 ULA
		"fe80::/10",      // IPv6 link-local
	}

  var privateNets []*net.IPNet
	for _, cidr := range privateCIDRs {
		_, netblock, err := net.ParseCIDR(cidr)
		if err == nil {
			privateNets = append(privateNets, netblock)
		}
	}
  return &DnsEnricher{
    DnsAddrs: make(map[string]string),
    privateIPNets: privateNets,
  }
}

func (e *DnsEnricher)isPublicIP(addr string) bool{
  ip := net.ParseIP(addr)
  if ip == nil{
    return false
  }

  for _, block := range e.privateIPNets{
    if block.Contains(ip){
      return false
    }
  } 

  return true
}

func (e *DnsEnricher) Enrich(ctx context.Context, event *pb.EbpfEvent) error{
  
  switch event.Payload.(type){
    case *pb.EbpfEvent_Network:
      var ip string
      payload,ok := event.Payload.(*pb.EbpfEvent_Network)
      if !ok{
        return errors.New("can not resolve ebpf event as a network event.")
      }
      if event.EventType == "connect"{
        if payload.Network.Daddrv4 != "" {
          ip = payload.Network.Daddrv4
        } else if payload.Network.Daddrv6 != "" {
          ip = payload.Network.Daddrv6
        }
      }else if event.EventType == "accept"{
        if payload.Network.Saddrv4 != ""{
          ip = payload.Network.Saddrv4
        } else if payload.Network.Saddrv6 != ""{
          ip = payload.Network.Saddrv6
        }
      }
      if ip == ""{
        return nil
      }
      
      if !e.isPublicIP(ip){
        payload.Network.ResolvedDomain = "<private>"
        return nil
      }
      e.mu.RLock()
      if dns, ok := e.DnsAddrs[ip]; ok{
        e.mu.RUnlock()
        event.Payload.(*pb.EbpfEvent_Network).Network.ResolvedDomain = dns
        return nil
      }
      e.mu.RUnlock()
      
      // Resolve DNS with timeout
      ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
      defer cancel()
      names, err := net.DefaultResolver.LookupAddr(ctx, ip)
      if err != nil || len(names)==0{
        e.mu.Lock()
        e.DnsAddrs[ip]= "<unresolved>"
        e.mu.Unlock()
        event.Payload.(*pb.EbpfEvent_Network).Network.ResolvedDomain= "<unresolved>"
        return nil
      }

      domain := names[0]
      
      e.mu.Lock()
      e.DnsAddrs[ip]= domain
      e.mu.Unlock()
      
      event.Payload.(*pb.EbpfEvent_Network).Network.ResolvedDomain= domain
  }

  return nil
}
