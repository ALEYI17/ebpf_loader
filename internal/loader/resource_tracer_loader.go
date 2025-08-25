package loader

import (
	"context"
	resourcetracer "ebpf_loader/bpf/resource_tracer"
	"ebpf_loader/internal/grpc/pb"
	"ebpf_loader/internal/metrics"
	"ebpf_loader/pkg/logutil"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
)

type ResourceTracerLoader struct{
  Objs *resourcetracer.ResourcetracerObjects
  links []link.Link
  resourceTable *ebpf.Map
}

func (rt *ResourceTracerLoader) add(l link.Link) {
	if l != nil {
		rt.links = append(rt.links, l)
	}
}

func NewResourceTrtacerLoader() (*ResourceTracerLoader,error){
  
  if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}
  
  objs := resourcetracer.ResourcetracerObjects{}

  if err := resourcetracer.LoadResourcetracerObjects(&objs, nil); err !=nil{
    return nil, err
  }

  rt := &ResourceTracerLoader{
    Objs: &objs,
    resourceTable: objs.ResourceTable,
  }

  kp,err := link.Kprobe("finish_task_switch.isra.0",objs.HandleFinishTaskSwitch,nil )
  if err !=nil{
    objs.Close()
    return nil,err
  }
  rt.add(kp)

  tracepoints := map[string]map[string]*ebpf.Program{
		"syscalls": {
			"sys_enter_mmap": objs.TpEnterMmap,
			"sys_exit_mmap":  objs.TpExitMmap,
			"sys_enter_munmap": objs.TpEnterMunmap,
			"sys_exit_munmap":  objs.TpExitMunmap,
			"sys_exit_brk":   objs.TpExitBrk,
			"sys_exit_read":    objs.TraceExitRead,
      "sys_exit_write": objs.TraceExitWrite,
		},
		"exceptions": {
      "page_fault_kernel": objs.HandlePageFaultKernel,
      "page_fault_user": objs.HandlePageFaultUser,
		},
	}

  for category, events := range tracepoints{
    for event, prog := range events{
      if prog ==nil{
        continue
      }
      tp, err := link.Tracepoint(category, event, prog, nil)

      if err != nil {
        rt.Close()
        return nil, err
      }

      rt.add(tp)
    }
  }

  
  return rt,nil

}


func (rt *ResourceTracerLoader) Close(){
  
	for i := len(rt.links) - 1; i >= 0; i-- {
		_ = rt.links[i].Close()
	}

	if rt.Objs != nil {
		rt.Objs.Close()
	}
}


func (rt *ResourceTracerLoader) Run(ctx context.Context, nodeName string) <-chan *pb.EbpfEvent {
  

  c := make(chan *pb.EbpfEvent)
  logger := logutil.GetLogger()

  go func (){
    defer close(c)

    interval := 15 * time.Second
    
    ticker := time.NewTicker(interval)
    for {
      select{
      case <- ctx.Done():
        logger.Info("Context cancelled, stopping loader...")
			  return
      case <- ticker.C:
        iter:= rt.resourceTable.Iterate()
        var key uint32
        var value resourcetracer.ResourcetracerResourceEventT

        for iter.Next(&key, &value){
          event := resourcetracer.GenerateGrpcMessage(value,nodeName)
          metrics.EventsTotal.WithLabelValues("resource").Inc()

          select {
          case <-ctx.Done():
            logger.Info("Context cancelled while sending event...")
            return
          case c <- event:
          }

          var zero resourcetracer.ResourcetracerResourceEventT
					if err := rt.resourceTable.Update(&key, &zero, ebpf.UpdateAny); err != nil {
						logger.Error("failed to reset resource_table entry" , zap.Uint32("key", key), zap.Error(err))
					}

          if err := iter.Err(); err != nil {
            metrics.ErrorsTotal.WithLabelValues("resource","decode").Inc()
					  logger.Error("failed to iterate resource_table", zap.Error(err))
				  }
        }
        
        
      }
    }

  }()
  return c
}
