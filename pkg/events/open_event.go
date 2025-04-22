package events

type open_event struct{
	Pid             uint32
	Uid             uint32
	Comm            [150]uint8
	Filename        [256]uint8
	_               [2]byte
	Flags           int32
	_               [4]byte
	TimestampNs     uint64
	Ret             int64
	Latency         uint64
	TimestampNsExit uint64
}
