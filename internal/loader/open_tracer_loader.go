package loader

import (
	"bytes"
	"context"
	opentracer "ebpf_loader/bpf/open_tracer"
	"ebpf_loader/internal/grpc/pb"
	"ebpf_loader/pkg/logutil"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
)

type OpentracerLoader struct {
	Objs *opentracer.OpentracerObjects
	Tc   link.Link
	Tcr  link.Link
	Rd   *ringbuf.Reader
}

func NewOpenTracerLoader() (*OpentracerLoader, error) {

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	objs := opentracer.OpentracerObjects{}

	if err := opentracer.LoadOpentracerObjects(&objs, nil); err != nil {
		return nil, err
	}
	defer objs.Close()

	tc, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleEnterOpenat, nil)

	if err != nil {
		objs.Close()
		return nil, err
	}

	tcr, err := link.Tracepoint("syscalls", "sys_exit_openat", objs.HandleExitOpenat, nil)
	if err != nil {
		objs.Close()
		tc.Close()
		return nil, err
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		objs.Close()
		tc.Close()
		tcr.Close()
		return nil, err
	}

	return &OpentracerLoader{
		Objs: &objs,
		Tc:   tc,
		Tcr:  tcr,
		Rd:   rd,
	}, nil
}

func (ot *OpentracerLoader) Close() {
	if ot.Rd != nil {
		ot.Rd.Close()
	}

	if ot.Tcr != nil {
		ot.Tcr.Close()
	}

	if ot.Tc != nil {
		ot.Tc.Close()
	}

	if ot.Objs != nil {
		ot.Objs.Close()
	}
}

func (ot *OpentracerLoader) Run(ctx context.Context, nodeName string) <-chan *pb.EbpfEvent {
	var events opentracer.OpentracerTraceSyscallEvent
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
				record, err := ot.Rd.Read()
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
					continue
				}

				event := opentracer.GenerateGrpcMessage(events, nodeName)

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
