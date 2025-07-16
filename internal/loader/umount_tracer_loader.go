package loader

import (
	"bytes"
	"context"
	umounttracer "ebpf_loader/bpf/umount_tracer"
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

type UmountTracerLoader struct{
  Objs *umounttracer.UmounttracerObjects
  Tc link.Link
  Tcr link.Link
  Rd *ringbuf.Reader
}

func NewUmountTracerLoader()(*UmountTracerLoader,error){

  if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

  objs := umounttracer.UmounttracerObjects{}

  if err:= umounttracer.LoadUmounttracerObjects(&objs, nil); err !=nil{
    return nil, err
  }
	defer objs.Close()

	tc, err := link.Tracepoint("syscalls", "sys_enter_umount", objs.HandleEnterUmount, nil)

	if err != nil {
		objs.Close()
		return nil, err
	}

	tcr, err := link.Tracepoint("syscalls", "sys_exit_umount", objs.HandleExitUmount, nil)
	if err != nil {
		objs.Close()
		tc.Close()
		return nil, err
	}

	rd, err := ringbuf.NewReader(objs.EventsUmount)
	if err != nil {
		objs.Close()
		tc.Close()
		tcr.Close()
		return nil, err
	}

  return &UmountTracerLoader{
    Objs: &objs,
    Tc: tc,
    Tcr: tcr,
    Rd: rd,
  },nil
}

func (ut *UmountTracerLoader) Close() {
	if ut.Rd != nil {
		ut.Rd.Close()
	}

	if ut.Tcr != nil {
		ut.Tcr.Close()
	}

	if ut.Tc != nil {
		ut.Tc.Close()
	}

	if ut.Objs != nil {
		ut.Objs.Close()
	}
}

func (mt *UmountTracerLoader) Run(ctx context.Context, nodeName string) <-chan *pb.EbpfEvent {
	var events umounttracer.UmounttracerMountEventT
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
          metrics.ErrorsTotal.WithLabelValues("umount","decode").Inc()
					continue
				}

				event := umounttracer.GenerateGrpcMessage(events, nodeName)
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

