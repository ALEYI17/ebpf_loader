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

	client, err := grpc.NewClient("localhost:8080")
	if err != nil {
		log.Fatalf("Error creating the client : %s", err)
	}

	log.Println("Client created =)")

	conf := config.LoadConfig()

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

	if err := client.Run(ctx, loaders, "Casa"); err != nil {
		log.Fatal("Error runing client")
	}

	defer client.Close()
	log.Println("After run client")
}
