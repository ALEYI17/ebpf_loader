package main

import (
	"context"
	"ebpf_loader/internal/grpc"
	"ebpf_loader/internal/loader"
	"ebpf_loader/pkg/programs"
	"log"
	"os"
	"os/signal"
	"syscall"
)


func main(){
  ctx, cancel := context.WithCancel(context.Background())

	// Handle graceful shutdown
	go func() {
		sigch := make(chan os.Signal, 1)
		signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigch
		log.Printf("Received signal: %s. Shutting down...", sig)
		cancel()
	}()

  client,err := grpc.NewClient("localhost:8080")
  if err != nil{
    log.Fatalf("Error creating the client : %s",err)
  }
 
  log.Println("Client created =)")  
  
  var loaders []programs.Load_tracer
  ol , err := loader.NewOpenTracerLoader()
  if err!=nil{
    log.Fatalf("Error creating the open loader %s",err)
  }
  defer ol.Close()
  loaders = append(loaders, ol)

  el,err := loader.NewExecvetracerLoader()
  if err !=nil {
    log.Fatalf("Error creating the execve loader %s", err)
  }
  defer el.Close()

  loaders = append(loaders, el)

  log.Println("Loader created =)")
  if err:= client.Run(ctx, loaders, "Casa"); err !=nil{
    log.Fatal("Error runing client")
  }
  
  defer client.Close()
  log.Println("After run client")
}
