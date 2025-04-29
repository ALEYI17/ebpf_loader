package config

import (
	"flag"
	"strings"
)

type Programsconfig struct{
  EnableProbes []string
}

func LoadConfig() *Programsconfig{
  var tracer string
  flag.StringVar(&tracer, "tracer", "", "Comma-separated list of eBPF probes to enable (e.g. 'execve,open')")

  flag.Parse()

  probeList:= strings.Split(tracer, ",")

  for i := range probeList{
    probeList[i] = strings.TrimSpace(probeList[i]) 
  }

  return &Programsconfig{EnableProbes: probeList}
}
