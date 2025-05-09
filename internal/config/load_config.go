package config

import (
	"ebpf_loader/pkg/logutil"
	"flag"
	"os"
	"strings"
)

type Programsconfig struct {
	EnableProbes []string
  ServerAdress string
  Serverport string
}

func LoadConfig() *Programsconfig {
  logger := logutil.GetLogger()
	var tracer,serverAddr,serverPort string
	flag.StringVar(&tracer, "tracer", "", "Comma-separated list of eBPF probes to enable (e.g. 'execve,open')")

  flag.StringVar(&serverAddr, "server-addr", "", "gRPC server address (e.g. 127.0.0.1)")

  flag.StringVar(&serverPort, "server-port", "", "gRPC server port (e.g. 50051)")

	flag.Parse()

  if serverAddr == "" {
		serverAddr = os.Getenv("SERVER_ADDR")
	}
	if serverPort == "" {
		serverPort = os.Getenv("SERVER_PORT")
	}

  if serverAddr ==""{
    logger.Fatal("Server address is missing")
  }

  if serverPort ==""{
    logger.Fatal("Server port is missing")
  }

  if tracer ==""{
    logger.Fatal("No probes specified for the program to run")
  }

	probeList := strings.Split(tracer, ",")

	for i := range probeList {
		probeList[i] = strings.TrimSpace(probeList[i])
	}

	return &Programsconfig{
    EnableProbes: probeList,
    ServerAdress: serverAddr,
    Serverport: serverPort,
  }
}
