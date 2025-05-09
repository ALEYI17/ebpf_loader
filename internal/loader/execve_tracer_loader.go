package loader

import (
	"bytes"
	"context"
	execvetracer "ebpf_loader/bpf/execve_tracer"
	"ebpf_loader/internal/grpc/pb"
	"ebpf_loader/pkg/logutil"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
)

type Execvetransferloader struct {
	Objs *execvetracer.ExecvetracerObjects
	Tc   link.Link
	Tcr  link.Link
	Rd   *ringbuf.Reader
}

func NewExecvetracerLoader() (*Execvetransferloader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	objs := execvetracer.ExecvetracerObjects{}
	if err := execvetracer.LoadExecvetracerObjects(&objs, nil); err != nil {
		return nil, err
	}

	tc, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleEnterExecve, nil)
	if err != nil {
		objs.Close()
		return nil, err
	}

	tcr, err := link.Tracepoint("syscalls", "sys_exit_execve", objs.HandleExitExecve, nil)
	if err != nil {
		objs.Close()
		tc.Close()
		return nil, err
	}

	rd, err := ringbuf.NewReader(objs.ExecEvents)
	if err != nil {
		objs.Close()
		tc.Close()
		tcr.Close()
		return nil, err
	}

	return &Execvetransferloader{
		Objs: &objs,
		Tc:   tc,
		Tcr:  tcr,
		Rd:   rd,
	}, nil
}

func (et *Execvetransferloader) Close() {
	if et.Rd != nil {
		et.Rd.Close()
	}

	if et.Tcr != nil {
		et.Tcr.Close()
	}

	if et.Tc != nil {
		et.Tc.Close()
	}

	if et.Objs != nil {
		et.Objs.Close()
	}

}

func (et *Execvetransferloader) Run(ctx context.Context, nodeName string) <-chan *pb.EbpfEvent {

	var events execvetracer.ExecvetracerTraceSyscallEvent

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
				record, err := et.Rd.Read()
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

				event := execvetracer.GenerateGrpcMessage(events, nodeName)

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
