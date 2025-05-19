package main

import (
	"context"
	"ebpf_loader/internal/config"
	"ebpf_loader/internal/grpc"
	"ebpf_loader/internal/loader"
	"ebpf_loader/pkg/containers"
	"ebpf_loader/pkg/logutil"
	"ebpf_loader/pkg/programs"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
  logutil.InitLogger()

  logger := logutil.GetLogger()
  defer logger.Sync()

	go func() {
		sigch := make(chan os.Signal, 1)
		signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigch
    logger.Info("Received signal, shutting down", zap.String("signal", sig.String()))
		cancel()
	}()

	
  runtimes :=containers.DetectRuntimeFromSystem()

  for _,runtime := range runtimes{
    logger.Info("Runtime detected", zap.String("runtime", runtime))
  }
  
	conf := config.LoadConfig()

  client, err := grpc.NewClient(conf.ServerAdress,conf.Serverport)
	if err != nil {
    logger.Fatal("Error creating the client", zap.Error(err))
	}

  logger.Info("Client created successfully")

	var loaders []programs.Load_tracer
	for _, program := range conf.EnableProbes {
		switch program {
		case "execve":
			el, err := loader.NewExecvetracerLoader()
			if err != nil {
        logger.Fatal("Error creating the execve loader", zap.Error(err))
			}
			defer el.Close()

			loaders = append(loaders, el)

		case "open":
			ol, err := loader.NewOpenTracerLoader()
			if err != nil {
        logger.Fatal("Error creating the open loader", zap.Error(err))
			}
			defer ol.Close()
			loaders = append(loaders, ol)
    case "chmod":
      cl , err := loader.NewChmodTracerLoader()
      if err != nil{
        logger.Fatal("Error creating the chmod loader", zap.Error(err))
      }
      defer cl.Close()
      loaders = append(loaders, cl)
		default:
      logger.Warn("Unknown program", zap.String("program", program))
		}
	}
  
  logger.Info("Loader(s) created successfully")
  defer client.Close()
	if err := client.Run(ctx, loaders, conf.Nodename); err != nil {
    logger.Error("Error running client", zap.Error(err))
    return
	}

  logger.Info("Client finished running")
}
