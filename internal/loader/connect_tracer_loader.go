package loader

import (
	"bytes"
	"context"
	connecttracer "ebpf_loader/bpf/connect_tracer"
	"ebpf_loader/internal/grpc/pb"
	"ebpf_loader/internal/metrics"
	"ebpf_loader/pkg/logutil"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
)

type ConnectLoader struct{
  Objs *connecttracer.ConnecttracerObjects
  Kp   link.Link
	Kpr  link.Link
  Kpv6 link.Link
  Kprv6 link.Link
  Rd   *ringbuf.Reader
}

func NewConnectTracer() (*ConnectLoader,error){
  if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}
  
  objs := connecttracer.ConnecttracerObjects{}

  if err := connecttracer.LoadConnecttracerObjects(&objs, nil);err !=nil{
    return nil, err
  }
  defer objs.Close()
  
  kp,err := link.Kprobe("tcp_v4_connect", objs.HandleTcpV4Connect, nil)
  if err != nil {
    objs.Close()
    return nil,err
  }

  kpr,err := link.Kretprobe("tcp_v4_connect", objs.HandleTcpV4ConnectRet,nil )
  if err !=nil{
    objs.Close()
    kp.Close()
    return nil,err
  }

  kp6,err := link.Kprobe("tcp_v6_connect", objs.HandleTcpV6Connect, nil)
  if err != nil {
    objs.Close()
    kp.Close()
    kpr.Close()
    return nil, err
  }

  kpr6,err := link.Kretprobe("tcp_v6_connect", objs.HandleTcpV6ConnectRet,nil)
  if err != nil {
    objs.Close()
    kp.Close()
    kpr.Close()
    kp6.Close()
    return nil, err
  }


  rd,err := ringbuf.NewReader(objs.ConnectEvents)
  if err !=nil{
    objs.Close()
    kp.Close()
    kpr.Close()
    kp6.Close()
    kpr6.Close()
    return nil,err
  }

  return &ConnectLoader{
    Objs: &objs,
    Kp: kp,
    Kpr: kpr,
    Kpv6: kp6,
    Kprv6: kpr6,
    Rd: rd,
  },nil

}

func (ct *ConnectLoader) Close() {
	if ct.Rd != nil {
		ct.Rd.Close()
	}

	if ct.Kpr != nil {
		ct.Kpr.Close()
	}

	if ct.Kp != nil {
		ct.Kp.Close()
	}

  if ct.Kpv6 !=nil{
    ct.Kpv6.Close()
  }

  if ct.Kpv6 !=nil{
    ct.Kprv6.Close()
  }

	if ct.Objs != nil {
		ct.Objs.Close()
	}
}

func (ct *ConnectLoader) Run(ctx context.Context, nodeName string) <-chan *pb.EbpfEvent{
  var events connecttracer.ConnecttracerSocketEventT
  c := make(chan *pb.EbpfEvent)
  logger := logutil.GetLogger()
  
  go func(){
    defer close(c)
    
    for{
      select{
      case <- ctx.Done():
        logger.Info("Context cancelled, stopping loader...")
				return
      default:
        record, err := ct.Rd.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						logger.Info("Ring buffer closed, exiting...")
						return
					}
					logger.Error("Reading error", zap.Error(err))
					continue
				}
        
        if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &events); err != nil {
					logger.Error("Parsing ringbuffer events", zap.Error(err))
          metrics.ErrorsTotal.WithLabelValues("connect","decode").Inc()
					continue
				}
        
        event := connecttracer.GenerateGrpcMessage(events, nodeName)
        metrics.EventsTotal.WithLabelValues("connect").Inc()
        select {
				case <-ctx.Done():
					logger.Info("Context cancelled while sending event...")
					return
				case c <- event:
				}

      }
    }
  }()
  return c
}
