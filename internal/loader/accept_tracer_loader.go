package loader

import (
	"bytes"
	"context"
	accepttracer "ebpf_loader/bpf/accept_tracer"
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


type AcceptLoader struct{
  Objs *accepttracer.AccepttracerObjects
  Kp link.Link
  Kpr link.Link
  Rd *ringbuf.Reader
}

func NewAcceptLoader() (*AcceptLoader,error){
  if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

  objs := accepttracer.AccepttracerObjects{}

  if err := accepttracer.LoadAccepttracerObjects(&objs, nil); err !=nil{
    return nil, err
  }
  defer objs.Close()

  kp,err := link.Kprobe("inet_csk_accept", objs.HandleAcceptEnter, nil)
  if err != nil {
    objs.Close()
    return nil,err
  }

  kpr,err := link.Kretprobe("inet_csk_accept", objs.HandleAcceptExit,nil )
  if err !=nil{
    objs.Close()
    kp.Close()
    return nil,err
  }

  rd,err := ringbuf.NewReader(objs.AcceptEvents)
  if err !=nil{
    objs.Close()
    kp.Close()
    kpr.Close()
    return nil,err
  }
  
  return &AcceptLoader{
    Objs: &objs,
    Kp: kp,
    Kpr: kpr,
    Rd: rd,
  },nil
}

func (at *AcceptLoader) Close() {
	if at.Rd != nil {
		at.Rd.Close()
	}

	if at.Kpr != nil {
		at.Kpr.Close()
	}

	if at.Kp != nil {
		at.Kp.Close()
	}

	if at.Objs != nil {
		at.Objs.Close()
	}
}

func (at *AcceptLoader) Run(ctx context.Context, nodeName string) <-chan *pb.EbpfEvent{
  var events accepttracer.AccepttracerSocketEventT
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
				record, err := at.Rd.Read()
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
          metrics.ErrorsTotal.WithLabelValues("accept","decode").Inc()
					continue
				}

				event := accepttracer.GenerateGrpcMessage(events, nodeName)
        metrics.EventsTotal.WithLabelValues("accept").Inc()
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
