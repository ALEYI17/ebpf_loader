package loader

import (
	mounttracer "ebpf_loader/bpf/mount_tracer"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
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
