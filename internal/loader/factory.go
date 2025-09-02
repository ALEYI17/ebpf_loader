package loader

import (
	"ebpf_loader/pkg/programs"
	"errors"
)


func NewEbpfLoader(program string) (programs.Load_tracer,error){ 

  switch program {
  case programs.Loaderexecve:
    return NewExecvetracerLoader()
  case programs.LoaderOpen:
    return NewOpenTracerLoader()
  case programs.LoaderChmod:
    return NewChmodTracerLoader()
  case programs.LoaderConnect:
    return NewConnectTracer()
  case programs.LoaderAccept:
    return NewAcceptLoader()
  case programs.LoaderPtrace:
    return NewPtraceTracerLoader()
  case programs.LoaderMmap:
    return NewMmapTracerLoader()
  case programs.LoaderMount:
    return NewMountTracerLoader()
  case programs.LoadUmount:
    return NewUmountTracerLoader()
  default:
    return nil,errors.New("Unsuported or unknow program")
  }

}

func NewEbpfBatchLoader(program string) (programs.Load_tracer_batch, error) {
    switch program {
    case programs.LoadResource:
        return NewResourceTracerLoader()
    case programs.LoadSyscallFreq:
        return NewSyscallFreqTracerLoader()
    default:
        return nil, errors.New("Unsupported or unknown batch program")
    }
}
