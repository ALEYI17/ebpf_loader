package containers

import (
	"ebpf_loader/pkg/containers/common"
	"ebpf_loader/pkg/logutil"
	"os"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func DetectRuntimeFromSystem() common.RuntimeDetection{
  logger := logutil.GetLogger()

  var runtimes []common.RuntimeDetection

  runtimes = detectByPort()

  preferred, ok:= selectPreferredRuntime(runtimes)

  if ok {
	  logger.Info("Selected container runtime", zap.String("runtime", preferred.Runtime))
    logger.Info("Selected container runtime socket", zap.String("socket", preferred.Socket))
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

func detectByPort() []common.RuntimeDetection{
  var results []common.RuntimeDetection

  for runtime,sockets := range common.RuntimeSockets {

    for _, path := range sockets{
      if info, err := os.Stat(path); err == nil && (info.Mode()&os.ModeSocket != 0){
        var cgroup string
        var err error
        cgroup, err = detectCgroupVersion()
        if err !=nil{
          cgroup = "unknow"
        }
        results = append(results, common.RuntimeDetection{Runtime: runtime,Socket: path,CgroupVersion:cgroup })
      }
    }
  }
  
  return results
}

func selectPreferredRuntime(detected []common.RuntimeDetection) (common.RuntimeDetection, bool) {
	for _, preferred := range common.RuntimePriority {
    var candidates []common.RuntimeDetection
		for _, r := range detected {
			if r.Runtime == preferred {
        candidates = append(candidates,r )
			}
		}

    if len(candidates)==0{
      continue
    }

    for _, preferredSocket := range common.RuntimeSockets[preferred] {
			for _, c := range candidates {
				if c.Socket == preferredSocket {
					return c, true
				}
			}
		}

    return candidates[0], true
	}
	return common.RuntimeDetection{}, false
}
