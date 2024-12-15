# The Watcher Auto Netstat

This is a tool for calling netstat at a chosen interval. Set it to run every minute, every 15 minutes, every half hour or hourly.

## Quick Start

⚠️NOTE: You'll get a security warning that the program is unsigned when running it on Windows and Linux. MacOS users may not be able to run the program at all unless you first run this command at your terminal:

```
xattr -d com.apple.quarantine ~/Downloads/thewatcher
```

(Assuming it's downloaded into your Downloads folder. Change the path to suit.)

Download and run the right program for your operating system:

Windows: [Download here](./bin/thewatcher.exe)
MacOS Silicon: [Download here](./bin/thewatcher)
MacOS Intel: [Download here](./bin/thewatcherOSX)
Linux AMD64: [Download here](./bin/thewatcher_linuxAMD64)
Linux ARM64: [Download here](./bin/thewatcher_linuxARM64)

## go-netstat

The bulk of the work was by Cihangir Akturk's `go-netstat` library. [Find the original go-netstat repository here](https://github.com/cakturk/go-netstat). I was just missing a way to call netstat programatically for infosec clients.

The `netstat` folder is a near 1:1 mirror of `go-netstat`. The only difference is a _darwin module included here for running and developing on MacOS.

## For Developers, DevOps, InfoSec

Feel free to remove the `cli` package from `main.go` and implement your own CLI prompts, if you want to write it as your own program.
