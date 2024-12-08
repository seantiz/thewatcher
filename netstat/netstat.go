package netstat

import (
	"fmt"
	"net"
)

var skStates = [...]string{
    "UNKNOWN",
    "ESTABLISHED",
    "SYN_SENT",
    "SYN_RECV",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "TIME_WAIT",
    "", // CLOSE
    "CLOSE_WAIT",
    "LAST_ACK",
    "LISTEN",
    "CLOSING",
}

// SockAddr represents an ip:port pair
type SockAddr struct {
	IP   net.IP
	Port uint16
}

func (s *SockAddr) String() string {
	return fmt.Sprintf("%v:%d", s.IP, s.Port)
}

// SockTabEntry type represents each line of the /proc/net/[tcp|udp]
type SockTabEntry struct {
	ino        string
	LocalAddr  *SockAddr
	RemoteAddr *SockAddr
	State      SkState
	UID        uint32
	Process    *Process
}

// Process holds the PID and process name to which each socket belongs
type Process struct {
	Pid  int
	Name string
}

func (p *Process) String() string {
	return fmt.Sprintf("%d/%s", p.Pid, p.Name)
}

// SkState type represents socket connection state
type SkState uint8

func (s SkState) String() string {
	return skStates[s]
}

// AcceptFn is used to filter socket entries. The value returned indicates
// whether the element is to be appended to the socket list.
type AcceptFn func(*SockTabEntry) bool

// NoopFilter - a test function returning true for all elements
func NoopFilter(*SockTabEntry) bool { return true }

func TCPSocks(accept AcceptFn) ([]SockTabEntry, error) {
    return OsTCPSocks(accept)
}

func TCP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
    return OsTCP6Socks(accept)
}

func UDPSocks(accept AcceptFn) ([]SockTabEntry, error) {
    return OsUDPSocks(accept)
}

func UDP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
    return OsUDP6Socks(accept)
}
