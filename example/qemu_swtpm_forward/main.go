package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CyberDefenseInstitute/tpmproxy"
)

var (
	sockFile         string
	swtpmAddr        string
	swtpmCtrlAddr    string
	terminateOnClose bool
)

func main() {
	flag.StringVar(&sockFile, "fwd-sock", filepath.Join(os.TempDir(), "qemu_swtpm_fwd.sock"), "forwarding unix socket file")
	flag.StringVar(&swtpmAddr, "swtpm", "127.0.0.1:2321", "swtpm address")
	flag.StringVar(&swtpmCtrlAddr, "swtpm-ctrl", "127.0.0.1:2322", "swtpm ctrl address")
	flag.BoolVar(&terminateOnClose, "terminate-on-close", true, "terminate relay on close")
	flag.Parse()

	relay := tpmproxy.NewQemuCtrlRelayer(sockFile,
		tpmproxy.NewTcpForwarderFactory(swtpmAddr),
		tpmproxy.NewTcpForwarderFactory(swtpmCtrlAddr),
		terminateOnClose,
		nil)
	if err := relay.Relay(); err != nil {
		fmt.Printf("error: %v\n", err)
	}
}
