package loader

import (
	"bytes"
	"context"
	mmaptracer "ebpf_loader/bpf/mmap_tracer"
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

type MmapTracerLoader struct{
  Objs *mmaptracer.MmaptracerObjects
  Tc link.Link
  Tcr link.Link
  Rd  *ringbuf.Reader
}

func NewMmapTracerLoader()(*MmapTracerLoader,error){

  if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

  objs := mmaptracer.MmaptracerObjects{}

  if err:= mmaptracer.LoadMmaptracerObjects(&objs, nil); err !=nil{
    return nil, err
  }
	defer objs.Close()

	tc, err := link.Tracepoint("syscalls", "sys_enter_mmap", objs.HandleEnterMmap, nil)

	if err != nil {
		objs.Close()
		return nil, err
	}

	tcr, err := link.Tracepoint("syscalls", "sys_exit_mmap", objs.HandleExitMmap, nil)
	if err != nil {
		objs.Close()
		tc.Close()
		return nil, err
	}

	rd, err := ringbuf.NewReader(objs.EventsMmap)
	if err != nil {
		objs.Close()
		tc.Close()
		tcr.Close()
		return nil, err
	}

  return &MmapTracerLoader{
    Objs: &objs,
    Tc: tc,
    Tcr: tcr,
    Rd: rd,
  },nil
}


func (mt *MmapTracerLoader) Close() {
	if mt.Rd != nil {
		mt.Rd.Close()
	}

	if mt.Tcr != nil {
		mt.Tcr.Close()
	}

	if mt.Tc != nil {
		mt.Tc.Close()
	}

	if mt.Objs != nil {
		mt.Objs.Close()
	}
}


func (mt *MmapTracerLoader) Run(ctx context.Context, nodeName string) <-chan *pb.EbpfEvent {
	var events mmaptracer.MmaptracerMmapEventT
	c := make(chan *pb.EbpfEvent)
  logger := logutil.GetLogger()

	go func() {
		defer close(c)

		for {
			select {
			case <-ctx.Done():
				// context was cancelled or timed out
				logger.Info("Context cancelled, stopping loader...")
				return
			default:
				record, err := mt.Rd.Read()
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
          metrics.ErrorsTotal.WithLabelValues("mmap","decode").Inc()
					continue
				}

				event := mmaptracer.GenerateGrpcMessage(events, nodeName)
        metrics.EventsTotal.WithLabelValues("mmap").Inc()

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
