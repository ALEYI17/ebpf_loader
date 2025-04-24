package main

import (
	"context"
	"ebpf_loader/internal/grpc"
	"ebpf_loader/internal/loader"
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

  ol , err := loader.NewOpenTracerLoader()
  if err!=nil{
    log.Fatalf("Error creating the loader %s",err)
  }
  defer ol.Close()

  log.Println("Loader created =)")
  if err:= client.Run(ctx, ol, "Casa"); err !=nil{
    log.Fatal("Error runing client")
  }
  
  defer client.Close()
  log.Println("After run client")
}
