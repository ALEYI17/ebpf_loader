package config

import (
	"flag"
	"log"
	"os"
	"strings"
)

type Programsconfig struct {
	EnableProbes []string
  ServerAdress string
  Serverport string
}

func LoadConfig() *Programsconfig {
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
    log.Fatal("server addr missing")
  }

  if serverPort ==""{
    log.Fatal("server port missing")
  }

  if tracer ==""{
    log.Fatal("Not specifie any type of program to run")
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
