package loader

import (
	"bytes"
	"context"
	mounttracer "ebpf_loader/bpf/mount_tracer"
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

type MountTracerLoader struct{
  Objs *mounttracer.MounttracerObjects
  Tc link.Link
  Tcr link.Link
  Rd *ringbuf.Reader
}

func NewMountTracerLoader()(*MountTracerLoader,error){

  if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

  objs := mounttracer.MounttracerObjects{}

  if err:= mounttracer.LoadMounttracerObjects(&objs, nil); err !=nil{
    return nil, err
  }
	defer objs.Close()

	tc, err := link.Tracepoint("syscalls", "sys_enter_mount", objs.HandleEnterMount, nil)

	if err != nil {
		objs.Close()
		return nil, err
	}

	tcr, err := link.Tracepoint("syscalls", "sys_exit_mount", objs.HandleExitMount, nil)
	if err != nil {
		objs.Close()
		tc.Close()
		return nil, err
	}

	rd, err := ringbuf.NewReader(objs.EventsMount)
	if err != nil {
		objs.Close()
		tc.Close()
		tcr.Close()
		return nil, err
	}

  return &MountTracerLoader{
    Objs: &objs,
    Tc: tc,
    Tcr: tcr,
    Rd: rd,
  },nil
}

func (mt *MountTracerLoader) Close() {
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


func (mt *MountTracerLoader) Run(ctx context.Context, nodeName string) <-chan *pb.EbpfEvent {
	var events mounttracer.MounttracerMountEventT
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
          metrics.ErrorsTotal.WithLabelValues("mount","decode").Inc()
					continue
				}

				event := mounttracer.GenerateGrpcMessage(events, nodeName)
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
