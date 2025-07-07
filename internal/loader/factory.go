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
  default:
    return nil,errors.New("Unsuported or unknow program")
  }

}
