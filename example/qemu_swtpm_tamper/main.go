package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/CyberDefenseInstitute/tpmproxy"
	"github.com/google/go-tpm/tpm2"
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
		&serverInterceptor{})
	if err := relay.Relay(); err != nil {
		fmt.Printf("error: %v\n", err)
	}
}

type serverInterceptor struct {
}

func (si *serverInterceptor) HandleRequest(request *tpmproxy.Request) []byte {
	return request.Raw
}

func (si *serverInterceptor) HandleResponse(request *tpmproxy.Request, response []byte) []byte {
	switch request.Hdr.CommandCode {
	case tpm2.TPMCCGetCapability:
		cmd := tpm2.GetCapability{}
		resp := tpm2.GetCapabilityResponse{}

		p := tpmproxy.RoughParser{
			RawRequest:  request.Raw,
			RawResponse: response,
			Cmd:         &cmd,
			Rsp:         &resp,
		}
		if err := p.Parse(); err != nil {
			break
		}
		if resp.CapabilityData.Capability != tpm2.TPMCapTPMProperties {
			break
		}
		props, err := resp.CapabilityData.Data.TPMProperties()
		if err != nil {
			break
		}
		for idx := range props.TPMProperty {
			prop := &props.TPMProperty[idx]
			if prop.Property == tpm2.TPMPTManufacturer {
				originalValue := prop.Value
				prop.Value = 0x58595A00
				fmt.Printf("Manufacturer tampered: %x to %x\n", originalValue, prop.Value)
			}
		}
		var buf bytes.Buffer
		buf.Write(response[:p.RspParameterOffset])
		if err := tpmproxy.Marshal(&buf, reflect.ValueOf(resp.MoreData)); err != nil {
			break
		}
		if err := tpmproxy.Marshal(&buf, reflect.ValueOf(resp.CapabilityData)); err != nil {
			break
		}
		return buf.Bytes()

	}
	return response
}
