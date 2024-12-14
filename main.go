package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"thewatcher/cli"
	"thewatcher/netstat"
)

var (
	udp       = flag.Bool("udp", false, "display UDP sockets")
	tcp       = flag.Bool("tcp", false, "display TCP sockets")
	listening = flag.Bool("lis", false, "display only listening sockets")
	all       = flag.Bool("all", false, "display both listening and non-listening sockets")
	resolve   = flag.Bool("res", false, "lookup symbolic names for host addresses")
	ipv4      = flag.Bool("4", false, "display only IPv4 sockets")
	ipv6      = flag.Bool("6", false, "display only IPv6 sockets")
	help      = flag.Bool("help", false, "display this help screen")
	logPath   = flag.String("saveto", "capturedlogs.txt", "path to the log file")
)

const (
	protoIPv4 = 0x01
	protoIPv6 = 0x02
)

func printHelp() {
	fmt.Println()
	fmt.Println("You can use these flags when running the program:")
	fmt.Println()
	flags := make([][2]string, 0)
	flag.VisitAll(func(f *flag.Flag) {
		flags = append(flags, [2]string{
			fmt.Sprintf("-%s", f.Name),
			f.Usage,
		})
	})

	for _, f := range flags {
		fmt.Printf("  %-15s %s\n", f[0], f[1])
	}
	fmt.Println()
}

func init() {
	flag.Usage = printHelp
}

func main() {
	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	fmt.Println("👀 The Watcher is here to look out for your network safety.")
	time.Sleep(4000 * time.Millisecond)

	logFile, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("We couldn't open the log file: %v\n", err)
		return
	}
	defer logFile.Close()

	var proto uint
	if *ipv4 {
		proto |= protoIPv4
	}
	if *ipv6 {
		proto |= protoIPv6
	}
	if proto == 0x00 {
		proto = protoIPv4 | protoIPv6
	}

	if os.Geteuid() != 0 {
		fmt.Println("Heads up! Some processes might not be visible. Run as admin for full visibility.")
		time.Sleep(500 * time.Millisecond)
	}

	interval, err := cli.ChooseInterval()
	if err != nil {
		switch err := err.(type) {
		case cli.InterruptError:
			fmt.Println("\n👋 You closed the program. See you next time.")
			os.Exit(0)
		default:
			fmt.Printf("Unexpected error: %v\n", err)
			os.Exit(1)
		}
	}

	var duration time.Duration
	switch interval {
	case "Every minute - INTENSE logging":
		duration = 1 * time.Minute
	case "Every 15 minutes":
		duration = 15 * time.Minute
	case "Every 30 minutes":
		duration = 30 * time.Minute
	case "Every hour":
		duration = 1 * time.Hour
	}

	fmt.Println("Watcher ACTIVATED.")
	time.Sleep(4000 * time.Millisecond)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			buffer := &bytes.Buffer{}
			fmt.Fprintf(buffer, "🔍 Connection capture at %s\n", time.Now().Format(time.RFC3339))
			fmt.Fprintf(buffer, "Proto %-23s %-23s %-12s %-16s\n",
				"Local Addr", "Foreign Addr", "State", "PID/Program name")

			// Socket filtering
			var fn netstat.AcceptFn
			switch {
			case *all:
				fn = func(*netstat.SockTabEntry) bool { return true }
			case *listening:
				fn = func(s *netstat.SockTabEntry) bool { return s.State == netstat.Listen }
			default:
				fn = func(s *netstat.SockTabEntry) bool { return s.State != netstat.Listen }
			}

			// Socket capture (TCP/UDP)
			if *tcp || !*udp {
				if proto&protoIPv4 == protoIPv4 {
					tabs, err := netstat.TCPSocks(fn)
					if err == nil {
						displaySockInfo("tcp", tabs, buffer)
					}
				}
				if proto&protoIPv6 == protoIPv6 {
					tabs, err := netstat.TCP6Socks(fn)
					if err == nil {
						displaySockInfo("tcp6", tabs, buffer)
					}
				}
			}

			if *udp {
				if proto&protoIPv4 == protoIPv4 {
					tabs, err := netstat.UDPSocks(netstat.NoopFilter)
					if err == nil {
						displaySockInfo("udp", tabs, buffer)
					}
				}
				if proto&protoIPv6 == protoIPv6 {
					tabs, err := netstat.UDP6Socks(netstat.NoopFilter)
					if err == nil {
						displaySockInfo("udp6", tabs, buffer)
					}
				}
			}

			if _, err := logFile.Write(buffer.Bytes()); err != nil {
				fmt.Printf("Failed to write to log file: %v\n", err)
				return
			}

			fmt.Printf("✅ The Watcher successfully captured the current connections at %s.\n", time.Now().Format("3.04 PM"))
			time.Sleep(7000 * time.Millisecond)
			if runtime.GOOS != "windows" {
				fmt.Println("👀 The Watcher is active. Press Ctrl+C anytime to stop.\033[?25h") // Show cursor
			} else {
				fmt.Println("👀 The Watcher is active. Press Ctrl+C anytime to stop.")
			}

			time.Sleep(duration)
		}
	}()

	<-sigs
	fmt.Println("\n👋 The Watcher is shutting down. See you next time.")
}

func displaySockInfo(proto string, s []netstat.SockTabEntry, buffer *bytes.Buffer) {
	lookup := func(skaddr *netstat.SockAddr) string {
		const IPv4Strlen = 17
		addr := skaddr.IP.String()
		if *resolve {
			names, err := net.LookupAddr(addr)
			if err == nil && len(names) > 0 {
				addr = names[0]
			}
		}
		if len(addr) > IPv4Strlen {
			addr = addr[:IPv4Strlen]
		}
		return fmt.Sprintf("%s:%d", addr, skaddr.Port)
	}

	for _, e := range s {
		p := ""
		if e.Process != nil {
			p = e.Process.String()
		}
		saddr := lookup(e.LocalAddr)
		daddr := lookup(e.RemoteAddr)
		fmt.Fprintf(buffer, "%-5s %-23.23s %-23.23s %-12s %-16s\n",
			proto, saddr, daddr, e.State, p)
	}
}
