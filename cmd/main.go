package main

import (
	"context"
	"ebpf_loader/internal/config"
	"ebpf_loader/internal/grpc"
	"ebpf_loader/internal/loader"
	"ebpf_loader/pkg/containers"
	"ebpf_loader/pkg/enrichers"
	"ebpf_loader/pkg/logutil"
	"ebpf_loader/pkg/programs"
	"os"
	"os/signal"
	"syscall"
	"time"

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

  runtimeClients,err := containers.NewRuntimeClientWithCache(ctx, 2*time.Minute, 30*time.Second)

  if err !=nil{
    logger.Fatal("Error creating the runtime client", zap.Error(err))
  }
  
  for _,runtimeClient := range runtimeClients{
    defer runtimeClient.Close()
  }
  
  logger.Info(" runtimeClient Client created successfully")

	conf := config.LoadConfig()

	var loaders []programs.Load_tracer
	for _, program := range conf.EnableProbes {
    loaderInstance , err := loader.NewEbpfLoader(program)
    if err != nil {
      logger.Warn("Unsupported or unknown program", zap.String("program", program), zap.Error(err))
      continue
    }
    logger.Info("Load successfully loader:", zap.String("Loader", program))
    defer loaderInstance.Close()
    loaders = append(loaders, loaderInstance)
  }
  
  logger.Info("Loader(s) created successfully")

  containerEnricher := enrichers.NewContainerenricher(runtimeClients)

  userEnricher := enrichers.NewUserEnriche()

  enricher := enrichers.NewMultiEnricher(containerEnricher,userEnricher)

  client, err := grpc.NewClient(conf.ServerAdress,conf.Serverport,enricher)
	if err != nil {
    logger.Fatal("Error creating the client", zap.Error(err))
	}

  logger.Info(" gRPC Client created successfully")

  defer client.Close()
	if err := client.Run(ctx, loaders, conf.Nodename); err != nil {
    logger.Error("Error running client", zap.Error(err))
    return
	}

  logger.Info("Client finished running")
}
