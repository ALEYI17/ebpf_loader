package config

import (
	"ebpf_loader/pkg/logutil"
	"flag"
	"os"
	"strings"

	"go.uber.org/zap"
)

type Programsconfig struct {
	EnableProbes []string
  ServerAdress string
  Serverport string
  PrometheusPort string
  Nodename string
}

func LoadConfig() *Programsconfig {
  logger := logutil.GetLogger()
	var tracer,serverAddr,serverPort,prometheusPort string
	flag.StringVar(&tracer, "tracer", "", "Comma-separated list of eBPF probes to enable (e.g. 'execve,open')")

  flag.StringVar(&serverAddr, "server-addr", "", "gRPC server address (e.g. 127.0.0.1)")

  flag.StringVar(&serverPort, "server-port", "", "gRPC server port (e.g. 50051)")

  flag.StringVar(&prometheusPort, "prometheus-port", "", "prometheus scrape port (e.g. 9090)")

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

  if prometheusPort == ""{
    prometheusPort = os.Getenv("PROMETHEUS_PORT")
  }

  if prometheusPort ==""{
    logger.Warn("Prometheus scrape port is missing")
  }

  if tracer ==""{
    tracer = os.Getenv("TRACER")
  }
  
  if tracer == ""{
    logger.Fatal("No probes specified for the program to run")
  }

  nodeName:= os.Getenv("NODE_NAME")

  if nodeName ==""{
    logger.Warn("NODE_NAME not set, falling back to os.Hostname")
    var err error
    nodeName ,err = os.Hostname()
    if err != nil{
      logger.Warn("Unknow host name ", zap.Error(err))
      nodeName = "unknown-host"
    }
  }

	probeList := strings.Split(tracer, ",")

	for i := range probeList {
		probeList[i] = strings.TrimSpace(probeList[i])
	}

	return &Programsconfig{
    EnableProbes: probeList,
    ServerAdress: serverAddr,
    Serverport: serverPort,
    PrometheusPort: prometheusPort,
    Nodename: nodeName,
  }
}
