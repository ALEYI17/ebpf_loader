package ptracetracer

import (
	"ebpf_loader/internal/grpc/pb"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type ptrace_event_t Ptracetracer ptrace_tracer.bpf.c

func GenerateGrpcMessage(raw PtracetracerPtraceEventT, nodeName string) *pb.EbpfEvent{

  return &pb.EbpfEvent{
		Pid:             raw.Pid,
		Uid:             raw.Uid,
		Gid:             raw.Gid,
		Ppid:            raw.Ppid,
		UserPid:         raw.UserPid,
		UserPpid:        raw.UserPpid,
		CgroupId:        raw.CgroupId,
		CgroupName:      unix.ByteSliceToString(raw.CgroupName[:]),
		Comm:            unix.ByteSliceToString(raw.Comm[:]),
		TimestampNs:     raw.TimestampNs,
		TimestampNsExit: raw.TimestampNsExit,
		LatencyNs:       raw.Latency,
		EventType:       "ptrace",
		NodeName:        nodeName,
		TimestampUnixMs: time.Now().UnixMilli(),
		Payload: &pb.EbpfEvent_Ptrace{ // oneof for NetworkEvent
			Ptrace: &pb.PtraceEvent{
				ReturnCode: raw.Ret,
				Addr: raw.Addr,
        TargetPid: raw.PidPtrace,
        Request: raw.Request,
        Data: raw.Data,
        RequestName: getPtraceRequestName(raw.Request),
			},
		},
	}
}

var ptraceRequests = map[int64]string{
    0:      "PTRACE_TRACEME",
    1:      "PTRACE_PEEKTEXT",
    2:      "PTRACE_PEEKDATA",
    3:      "PTRACE_PEEKUSER",
    4:      "PTRACE_POKETEXT",
    5:      "PTRACE_POKEDATA",
    6:      "PTRACE_POKEUSER",
    7:      "PTRACE_CONT",
    8:      "PTRACE_KILL",
    9:      "PTRACE_SINGLESTEP",
    12:     "PTRACE_GETREGS",
    13:     "PTRACE_SETREGS",
    14:     "PTRACE_GETFPREGS",
    15:     "PTRACE_SETFPREGS",
    16:     "PTRACE_ATTACH",
    17:     "PTRACE_DETACH",
    18:     "PTRACE_GETFPXREGS",
    19:     "PTRACE_SETFPXREGS",
    24:     "PTRACE_SYSCALL",
    0x4200: "PTRACE_SETOPTIONS",
    0x4201: "PTRACE_GETEVENTMSG",
    0x4202: "PTRACE_GETSIGINFO",
    0x4203: "PTRACE_SETSIGINFO",
}

// getPtraceRequestName returns the human-readable name, or a default string.
func getPtraceRequestName(req int64) string {
    if name, found := ptraceRequests[req]; found {
        return name
    }
    return fmt.Sprintf("PTRACE_UNKNOWN_%d", req)
}
