package ebpf

type Event string

const (
	Syscall      Event = "syscall"
	Exec         Event = "exec"
	Open         Event = "open"
	Netwrok      Event = "network"
	DNS          Event = "dns"
	Capabilities Event = "capabilities"
)
