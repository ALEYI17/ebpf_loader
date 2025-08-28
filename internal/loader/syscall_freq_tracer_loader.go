package loader

import (
	"context"
	syscallfreq "ebpf_loader/bpf/syscall_freq"
	"ebpf_loader/internal/grpc/pb"
	"ebpf_loader/internal/metrics"
	"ebpf_loader/pkg/logutil"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
)

type SyscallFreqTracerLoader struct{
  Objs *syscallfreq.SysFreqtracerObjects
  Tc link.Link
  freqTable *ebpf.Map
}

func NewSyscallFreqTracerLoader() (*SyscallFreqTracerLoader,error){

  if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

  objs := syscallfreq.SysFreqtracerObjects{}
  
  if err := syscallfreq.LoadSysFreqtracerObjects(&objs, nil);err !=nil{
    return nil, err
  }

  sft := &SyscallFreqTracerLoader{
    Objs: &objs,
    freqTable: objs.SyscountMap,
  }

  tc,err := link.Tracepoint("raw_syscalls", "sys_enter", objs.TraceSysEnter, nil)

  if err!=nil{
    sft.Close()
    return nil, err
  }

  sft.Tc = tc
  return sft,nil

}

func (sft *SyscallFreqTracerLoader) Close(){
  if sft.Tc != nil {
		sft.Tc.Close()
	}

	if sft.Objs != nil {
		sft.Objs.Close()
	}

}


func (sft *SyscallFreqTracerLoader) Run(ctx context.Context, nodeName string)<-chan *pb.EbpfEvent{

  c := make(chan *pb.EbpfEvent)
  logger := logutil.GetLogger()

  go func() {

    defer close(c)
    interval := 2 * time.Second
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    for{

      select{
      case <- ctx.Done():
        logger.Info("Context cancelled, stopping loader...")
			  return
      case <- ticker.C:
        iter := sft.freqTable.Iterate()
        var key syscallfreq.SysFreqtracerSyscallKey // struct { Pid uint32; SyscallNr uint32 }
        var value uint64

        for iter.Next(&key, &value){
          event := syscallfreq.GenerateGrpcMessage(key, value, nodeName)
          metrics.EventsTotal.WithLabelValues("syscall_freq").Inc()

          select{
          case <- ctx.Done():
            logger.Info("Context cancelled while sending syscall freq event...")
            return
          case c <- event: 
          }

          zero := uint64(0)
          if err := sft.freqTable.Update(&key, &zero, ebpf.UpdateAny);err !=nil{
            logger.Error("failed to reset syscall_freq entry",
                            zap.Uint32("pid", key.Pid),
                            zap.Uint32("syscall", key.SyscallNr),
                            zap.Error(err))
          }

          if err := iter.Err(); err !=nil{
            metrics.ErrorsTotal.WithLabelValues("syscall_freq", "decode").Inc()
            logger.Error("failed to iterate syscall_freq table", zap.Error(err))
          }
        }
      }
    }
  }()

  return c
}
