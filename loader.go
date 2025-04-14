package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type open_event ebpf open_tracer/open_tracer.bpf.c

func main(){
  
  log:= log.New(os.Stdout, "Open_at", 0)
  stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

  if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

  objs := ebpfObjects{}

  if err:= loadEbpfObjects(&objs, nil); err != nil {
    log.Fatalf("Error loading obj: %v",err)
  }

  defer objs.Close()

  kp,err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleEnterOpenat, nil)

  if err != nil {
    log.Fatalf("Error opening tracepoint for openat enter : %v",err)
  } 

  defer kp.Close()

  kpr,err := link.Tracepoint("syscalls", "sys_exit_openat", objs.HandleExitOpenat, nil)

  if err != nil {
    log.Fatalf("Error opening tracepoint for openat enter : %v",err)
  }

  defer kpr.Close()

  rd,err := ringbuf.NewReader(objs.Events)

  if err != nil {
    log.Fatalf("Error opening ringbuffer",err)
  }

  defer rd.Close()

  go func(){
    <- stopper

    if err:= rd.Close();err!=nil{
      log.Fatalf("Closing rigbuffer reader:",err)
    }
  }()
  
  var events ebpfOpenEvent
  
  for{
    record,err := rd.Read()

    if err != nil{
      if errors.Is(err, ringbuf.ErrClosed){
        log.Printf("Received signal, exiting...")
        return
      }
      
      log.Printf("Reading from reader: %s", err)
      continue

    }

    if err:= binary.Read(bytes.NewBuffer(record.RawSample),binary.LittleEndian,&events); err!= nil{
      log.Printf("Parsing ringbuffer events: %s", err)
      continue 
    }

    logOpenat(log,events)

  }
}

func logOpenat(logger *log.Logger, event ebpfOpenEvent) {
message := fmt.Sprintf(
		"Openat syscall - syscall: openat, pid: %d, uid: %d, command: %s, filename: %s, flags: %d, timestamp: %d, return: %d, latency_ns: %d",
		event.Pid,
		event.Uid,
		unix.ByteSliceToString(event.Comm[:]),
		unix.ByteSliceToString(event.Filename[:]),
		event.Flags,
		event.TimestampNs,
		event.Ret,
		event.Latency,
	)
	logger.Println(message)}


