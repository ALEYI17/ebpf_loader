package main

import (
	"context"
	"ebpf_loader/internal/config"
	"ebpf_loader/internal/grpc"
	"ebpf_loader/internal/loader"
	"ebpf_loader/pkg/programs"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())

	// Handle graceful shutdown
	go func() {
		sigch := make(chan os.Signal, 1)
		signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigch
		log.Printf("Received signal: %s. Shutting down...", sig)
		cancel()
	}()

	
	conf := config.LoadConfig()

  client, err := grpc.NewClient(conf.ServerAdress,conf.Serverport)
	if err != nil {
		log.Fatalf("Error creating the client : %s", err)
	}

	log.Println("Client created =)")

	var loaders []programs.Load_tracer
	for _, program := range conf.EnableProbes {
		switch program {
		case "execve":
			el, err := loader.NewExecvetracerLoader()
			if err != nil {
				log.Fatalf("Error creating the execve loader %s", err)
			}
			defer el.Close()

			loaders = append(loaders, el)

		case "open":
			ol, err := loader.NewOpenTracerLoader()
			if err != nil {
				log.Fatalf("Error creating the open loader %s", err)
			}
			defer ol.Close()
			loaders = append(loaders, ol)
		default:
			log.Printf("Unknow program: %s", program)
		}
	}

	log.Println("Loader created =)")
  defer client.Close()
	if err := client.Run(ctx, loaders, "Casa"); err != nil {
    log.Printf("Error runing client: %s",err)
    return
	}


	log.Println("After run client")
}
