package main

import (
    "flag"
    "fmt"
    "net"
    "os"
    "os/signal"
    "syscall"
    "time"
    "bytes"
    "runtime"

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
    logPath   = flag.String("saveto", "watcher.txt", "path to the log file")
    interval  = flag.Duration("interval", 15*time.Minute, "interval between checks")
)

const (
    protoIPv4 = 0x01
    protoIPv6 = 0x02
)

func main() {
    flag.Parse()

    if *help {
        fmt.Println("Welcome to The Watcher! Here's how you can use it:")
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

    fmt.Println("Watcher ACTIVATED.")
    time.Sleep(4000 * time.Millisecond)

    // Set up channel to listen for interrupt signals
    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

    // Main loop to keep the program running
    go func() {
        for {
            buffer := &bytes.Buffer{}
            fmt.Fprintf(buffer, "🔍 Connection capture at %s\n", time.Now().Format(time.RFC3339))
            fmt.Fprintf(buffer, "Proto %-23s %-23s %-12s %-16s\n",
                "Local Addr", "Foreign Addr", "State", "PID/Program name")

            // Socket filtering function
            var fn netstat.AcceptFn
            switch {
            case *all:
                fn = func(*netstat.SockTabEntry) bool { return true }
            case *listening:
                fn = func(s *netstat.SockTabEntry) bool { return s.State == netstat.Listen }
            default:
                fn = func(s *netstat.SockTabEntry) bool { return s.State != netstat.Listen }
            }

            // Capture TCP sockets
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

            // Capture UDP sockets
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

            // Write buffer to file
            if _, err := logFile.Write(buffer.Bytes()); err != nil {
                fmt.Printf("Failed to write to log file: %v\n", err)
                return
            }

			fmt.Printf("✅ The Watcher successfully captured the current connections at %s.\n", time.Now().Format(time.RFC3339))
            time.Sleep(7000 * time.Millisecond)

            if runtime.GOOS != "windows" {
                fmt.Println("👀 The Watcher is active. Press Ctrl+C anytime to stop.\033[?25h") // Show cursor
            } else {
                fmt.Println("👀 The Watcher is active. Press Ctrl+C anytime to stop.")
            }

            time.Sleep(*interval)
        }
    }()

    // Wait for interrupt signal
    <-sigs
    fmt.Println("\n👋 The Watcher is shutting down. Goodbye!")
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
