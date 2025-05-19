package containers

import (
	"ebpf_loader/pkg/logutil"
	"os"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const (
	RuntimeDocker     = "docker"
	RuntimeContainerd = "containerd"
	RuntimeCrio       = "crio"
	RuntimePodman     = "podman"
)

var runtimePriority = []string{
	RuntimeContainerd,
	RuntimeCrio,
  RuntimeDocker,
	RuntimePodman,
}

func DetectRuntimeFromSystem() string{
  logger := logutil.GetLogger()

  var runtimes []string

  cgroupVersion , err:= detectCgroupVersion()

  if err != nil{
    logger.Warn("Cannot detect cgroup version", zap.Error(err))
  }

  logger.Info("Cgroup version is ", zap.String("cgroupVersion", cgroupVersion))

  if cgroupVersion == "cgroup1"{
    runtimes,err = detectByPath()
    if err != nil || len(runtimes) == 0{
      logger.Info("Detecting by port")
      runtimes = detectByPort()
    }
  }else{
    logger.Info("Detecting by port")
    runtimes = detectByPort()
  }

  preferred, ok:= selectPreferredRuntime(runtimes)

  if ok {
	  logger.Info("Selected container runtime", zap.String("runtime", preferred))
  }else {
    logger.Warn("No known container runtime found")
  }

  return preferred
}

func detectCgroupVersion() (string,error){
  var statfs unix.Statfs_t

  err := unix.Statfs("/sys/fs/cgroup", &statfs)

  if err != nil{
    return "", err
  }

  switch statfs.Type{
  case unix.CGROUP2_SUPER_MAGIC:
    return "cgroup2", nil
  case unix.TMPFS_MAGIC:
    return "cgroup1",nil
  default:
    return "unknow", nil
  }
}

func detectByPath() ([]string,error){
  var runtimes []string
  data, err := os.ReadFile("/proc/self/cgroup")

  if err == nil{
    content := string(data)

    if strings.Contains(content, RuntimeDocker){
      runtimes = append(runtimes, RuntimeDocker)
    }

    if strings.Contains(content, RuntimeContainerd){
      runtimes = append(runtimes, RuntimeContainerd)
    }

    if strings.Contains(content, RuntimeCrio) {
		  runtimes = append(runtimes, RuntimeCrio)
		}

    return runtimes,nil
  }
  return runtimes,err
}

func detectByPort() []string{
  var runtimes []string

  sockets := map[string]string{
    RuntimeDocker : "/var/run/docker.sock",
    RuntimeContainerd : "/run/containerd/containerd.sock",
    RuntimeCrio:        "/var/run/crio/crio.sock",
    RuntimePodman:      "/run/podman/podman.sock",
  }
  
  
  for runtime,sockets := range sockets{
    if info, err := os.Stat(sockets); err ==nil && (info.Mode() & os.ModeSocket != 0) {
      runtimes = append(runtimes, runtime)
    }
  }
  
  return runtimes
}

func selectPreferredRuntime(detected []string) (string, bool) {
	for _, preferred := range runtimePriority {
		for _, r := range detected {
			if r == preferred {
				return r, true
			}
		}
	}
	return "", false
}
