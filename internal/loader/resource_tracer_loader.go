package loader

import (
	"bytes"
	"context"
	resourcetracer "ebpf_loader/bpf/resource_tracer"
	"ebpf_loader/internal/grpc/pb"
	"ebpf_loader/internal/metrics"
	"ebpf_loader/pkg/logutil"
	"encoding/binary"
	"errors"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
)

type ResourceTracerLoader struct{
  Objs *resourcetracer.ResourcetracerObjects
  Kp    link.Link
  Rd    *perf.Reader
}

func NewResourceTrtacerLoader() (*ResourceTracerLoader,error){
  
  if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}
  
  objs := resourcetracer.ResourcetracerObjects{}

  if err := resourcetracer.LoadResourcetracerObjects(&objs, nil); err !=nil{
    return nil, err
  }
  defer objs.Close()

  kp,err := link.Kprobe("finish_task_switch.isra.0",objs.HandleFinishTaskSwitch,nil )
  if err !=nil{
    objs.Close()
    return nil,err
  }

  rd, err := perf.NewReader(objs.Events, os.Getpagesize())
  if err !=nil {
    objs.Close()
    kp.Close()
    return nil,err
  }

  return &ResourceTracerLoader{
    Objs: &objs,
    Kp: kp,
    Rd: rd,
  },nil

}


func (rt *ResourceTracerLoader) Close(){
  if rt.Rd != nil {
		rt.Rd.Close()
	}

	if rt.Kp != nil {
		rt.Kp.Close()
	}

	if rt.Objs != nil {
		rt.Objs.Close()
	}
}


func (rt *ResourceTracerLoader) Run(ctx context.Context, nodeName string) <-chan *pb.EbpfEvent {
  
  var events resourcetracer.ResourcetracerResourceEventT

  c := make(chan *pb.EbpfEvent)
  logger := logutil.GetLogger()

  go func (){
    defer close(c)

    interval := 1 * time.Second
    
    ticker := time.NewTicker(interval)
    for range ticker.C{
      select{
      case <- ctx.Done():
        logger.Info("Context cancelled, stopping loader...")
			  return
      default:
        record, err := rt.Rd.Read()
        if err !=nil{
          if errors.Is(err, perf.ErrClosed){
            logger.Info("perf buffer closed, exiting...")
						return
          }
          logger.Info("Reading error", zap.Error(err))
          continue
        }

        if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &events); err != nil{
          logger.Error("Parsing perf events", zap.Error(err))
          metrics.ErrorsTotal.WithLabelValues("resource","decode").Inc()
					continue
        }

        event := resourcetracer.GenerateGrpcMessage(events,nodeName)
        metrics.EventsTotal.WithLabelValues("umount").Inc()

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
