package events

type execve_event struct{
  Pid uint32
  Uid uint32
  TimestampNs     uint64
	Ret             int64
	Latency         uint64
	TimestampNsExit uint64
}
