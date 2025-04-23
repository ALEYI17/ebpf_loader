package loader

import (
	opentracer "ebpf_loader/bpf/open_tracer"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type OpentracerLoader struct{
  Objs *opentracer.OpentracerObjects
  Tc link.Link
  Tcr link.Link
  Rd *ringbuf.Reader
}

func LoadOpenTracer() (*OpentracerLoader,error){
  
  if err := rlimit.RemoveMemlock();err != nil{
    return nil,err
  }
  
  objs := opentracer.OpentracerObjects{}

  if err := opentracer.LoadOpentracerObjects(&objs,nil); err!=nil{
    return nil,err
  }  
  defer objs.Close()

  tc,err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleEnterOpenat, nil)

  if err != nil{
    objs.Close()
    return nil,err
  }
  
  tcr,err := link.Tracepoint("syscalls", "sys_exit_openat", objs.HandleExitOpenat, nil)
  if err !=nil{
    objs.Close()
    tc.Close()
    return nil,err
  }
  
  rd,err := ringbuf.NewReader(objs.Events)
  if err != nil {
    objs.Close()
    tc.Close()
    tcr.Close()
    return nil,err
  }

  
  return &OpentracerLoader{
    Objs: &objs,
    Tc: tc,
    Tcr: tcr,
    Rd: rd,
  },nil
}

func (ot *OpentracerLoader) Close(){
  if ot.Rd != nil{
    ot.Rd.Close()
  }

  if ot.Tcr != nil{
    ot.Tcr.Close()
  }

  if ot.Tc != nil{
    ot.Tc.Close()
  }

  if ot.Objs != nil {
    ot.Objs.Close()
  }
}
