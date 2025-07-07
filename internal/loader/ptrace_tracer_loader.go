package loader

import (
	"bytes"
	"context"
	ptracetracer "ebpf_loader/bpf/ptrace_tracer"
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

type PtraceTracerLoader struct{
  Objs *ptracetracer.PtracetracerObjects
	Tc   link.Link
	Tcr  link.Link
	Rd   *ringbuf.Reader
}

func NewPtraceTracerLoader() (*PtraceTracerLoader, error){
  
  if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	objs := ptracetracer.PtracetracerObjects{}

  if err := ptracetracer.LoadPtracetracerObjects(&objs, nil); err != nil {
		return nil, err
	}
	defer objs.Close()

  tc, err := link.Tracepoint("syscalls", "sys_enter_ptrace", objs.HandleEnterPtrace, nil)
  if err !=nil {
    objs.Close()
		return nil, err
  }

  tcr, err := link.Tracepoint("syscalls", "sys_exit_ptrace", objs.HandleExitPtrace, nil)
	if err != nil {
		objs.Close()
		tc.Close()
		return nil, err
	}

	rd, err := ringbuf.NewReader(objs.EventsPtrace)
	if err != nil {
		objs.Close()
		tc.Close()
		tcr.Close()
		return nil, err
	}

  return &PtraceTracerLoader{
    Objs: &objs,
    Tc: tc,
    Tcr: tcr,
    Rd: rd,
  },nil
}


func (pt *PtraceTracerLoader) Close() {
	if pt.Rd != nil {
		pt.Rd.Close()
	}

	if pt.Tcr != nil {
		pt.Tcr.Close()
	}

	if pt.Tc != nil {
		pt.Tc.Close()
	}

	if pt.Objs != nil {
		pt.Objs.Close()
	}
}


func (pt *PtraceTracerLoader) Run(ctx context.Context, nodeName string) <-chan *pb.EbpfEvent {
	var events ptracetracer.PtracetracerPtraceEventT
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
				record, err := pt.Rd.Read()
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
          metrics.ErrorsTotal.WithLabelValues("ptrace","decode").Inc()
					continue
				}

				event := ptracetracer.GenerateGrpcMessage(events, nodeName)
        metrics.EventsTotal.WithLabelValues("ptrace").Inc()

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
