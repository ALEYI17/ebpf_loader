package loader

import (
	"context"
	syscallfreq "ebpf_loader/bpf/syscall_freq"
	"ebpf_loader/internal/grpc/pb"
	"ebpf_loader/internal/metrics"
	"ebpf_loader/pkg/logutil"
	"ebpf_loader/pkg/programs"
	"encoding/json"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
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
        var entries []struct {
					Key   syscallfreq.SysFreqtracerSyscallKey
					Value uint64
				}
        for iter.Next(&key, &value){
          k := key
					entries = append(entries, struct {
						Key   syscallfreq.SysFreqtracerSyscallKey
						Value uint64
					}{Key: k, Value: value})
        }
        if err := iter.Err(); err != nil {
					metrics.ErrorsTotal.WithLabelValues("syscall_freq", "decode").Inc()
					logger.Error("failed to iterate syscall_freq table", zap.Error(err))
					continue
				}
        pidMap := make(map[uint32]map[uint32]uint64)
        metaMap := make(map[uint32]*syscallfreq.SysFreqtracerProcessMetadataT)

        for _,e := range entries{
          pid := e.Key.Pid
          syscall := e.Key.SyscallNr
          if _,ok := pidMap[pid]; !ok{
            pidMap[pid] = make(map[uint32]uint64)
          }

          if _,ok := metaMap[pid];!ok{
            var meta syscallfreq.SysFreqtracerProcessMetadataT
            err :=sft.metadataTable.Lookup(&pid, &meta)
            if err !=nil{
              if err := sft.freqTable.Delete(&e.Key);err !=nil{
                logger.Warn("failed to delete stale syscount_map entry",
                  zap.Uint32("pid", e.Key.Pid),
                  zap.Uint32("syscall", e.Key.SyscallNr),
                  zap.Error(err))
              }
              continue
            }
            m := meta
            metaMap[pid] = &m
          }
          
          pidMap[pid][syscall] += e.Value
          metrics.EventsTotal.WithLabelValues("syscall_freq").Inc()

          zero := uint64(0)
          if err := sft.freqTable.Update(&e.Key, &zero, ebpf.UpdateAny);err !=nil{
            logger.Error("failed to reset syscall_freq entry",
                            zap.Uint32("pid", e.Key.Pid),
                            zap.Uint32("syscall", e.Key.SyscallNr),
                            zap.Error(err))
          }

        }
        
        now := time.Now().UnixMilli()
        var batch []*pb.EbpfEvent
        for pid, counts := range pidMap{
          jsonBytes, err := json.Marshal(counts)
          if err != nil {
            logger.Error("failed to marshal counts map", zap.Error(err))
            continue
          }
          ev := &pb.EbpfEvent{
              Pid:             pid,
              TimestampUnixMs: now,
              EventType:       "syscall_freq_agg",
              NodeName:        nodeName,
              Payload: &pb.EbpfEvent_SyscallFreqAgg{
                  SyscallFreqAgg: &pb.SyscallFreqAgg{
                      VectorJson: string(jsonBytes),
                  },
              },
          }

          if meta,ok := metaMap[pid];ok{
            ev.Uid = meta.Uid
            ev.Gid = meta.Gid
            ev.Ppid = meta.Ppid
            ev.UserPid = meta.UserPid
            ev.UserPpid = meta.UserPpid
            ev.CgroupId = meta.CgroupId
            ev.CgroupName = unix.ByteSliceToString(meta.CgroupName[:])
            ev.Comm = unix.ByteSliceToString(meta.Comm[:])

          }

          batch = append(batch, ev)
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
