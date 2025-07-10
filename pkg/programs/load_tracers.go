package programs

import (
	"context"
	"ebpf_loader/internal/grpc/pb"
)

type Load_tracer interface {
	Close()
	Run(context.Context, string) <-chan *pb.EbpfEvent
}

const (
	LoaderOpen     = "open"
	Loaderexecve = "execve"
  LoaderChmod = "chmod"
  LoaderConnect = "connect"
  LoaderAccept = "accept"
  LoaderPtrace = "ptrace"
  LoaderMmap = "mmap"
  LoaderMount = "mount"
)

