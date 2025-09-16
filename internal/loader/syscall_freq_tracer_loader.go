package loader

import (
	"context"
	syscallfreq "ebpf_loader/bpf/syscall_freq"
	"ebpf_loader/internal/grpc/pb"
	"ebpf_loader/internal/metrics"
	"ebpf_loader/pkg/logutil"
	"ebpf_loader/pkg/programs"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
)

type SyscallFreqTracerLoader struct{
  Objs *syscallfreq.SysFreqtracerObjects
  Tc link.Link
  Tcexit link.Link
  freqTable *ebpf.Map
  metadataTable *ebpf.Map
  inteval int
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
    metadataTable: objs.MetaCache,
    inteval: 10,
  }

  tc,err := link.Tracepoint("raw_syscalls", "sys_enter", objs.TraceSysEnter, nil)

  if err!=nil{
    sft.Close()
    return nil, err
  }
  sft.Tc = tc

  tce,err := link.Tracepoint("sched", "sched_process_exit", objs.HandleSchedProcessExit, nil)
  if err !=nil{
    sft.Close()
    return nil,err
  }
  sft.Tcexit = tce

  return sft,nil

}

func (sft *SyscallFreqTracerLoader) Close(){
  if sft.Tc != nil {
		sft.Tc.Close()
	}

  if sft.Tcexit !=nil{
    sft.Tcexit.Close()
  }

	if sft.Objs != nil {
		sft.Objs.Close()
	}

}


func (sft *SyscallFreqTracerLoader) Run(ctx context.Context, nodeName string)<-chan *pb.Batch{

  c := make(chan *pb.Batch)
  logger := logutil.GetLogger()

  go func() {

    defer close(c)
    interval := time.Duration(sft.inteval) * time.Second
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

        var batch []*pb.EbpfEvent
        for iter.Next(&key, &value){
          var meta syscallfreq.SysFreqtracerProcessMetadataT
          err :=sft.metadataTable.Lookup(&key.Pid, &meta)
          if err !=nil{
            if err := sft.freqTable.Delete(&key);err !=nil{
              logger.Warn("failed to delete stale syscount_map entry",
                zap.Uint32("pid", key.Pid),
                zap.Uint32("syscall", key.SyscallNr),
                zap.Error(err))
            }
            continue
          }
          event := syscallfreq.GenerateGrpcMessage(key, value, &meta,nodeName)
          metrics.EventsTotal.WithLabelValues("syscall_freq").Inc()
          batch = append(batch, event)

          zero := uint64(0)
          if err := sft.freqTable.Update(&key, &zero, ebpf.UpdateAny);err !=nil{
            logger.Error("failed to reset syscall_freq entry",
                            zap.Uint32("pid", key.Pid),
                            zap.Uint32("syscall", key.SyscallNr),
                            zap.Error(err))
          }

        }
        
        if err := iter.Err(); err !=nil{
          metrics.ErrorsTotal.WithLabelValues("syscall_freq", "decode").Inc()
          logger.Error("failed to iterate syscall_freq table", zap.Error(err))
        }

        if len(batch) >0{
          batchMessage := &pb.Batch{
            Batch: batch,
            Type: programs.LoadSyscallFreq,
          }
          select{
          case <- ctx.Done():
            logger.Info("Context cancelled while sending syscall freq batch...")
            return
          case c <- batchMessage:
          }
        }
      }
    }
  }()

  return c
}
