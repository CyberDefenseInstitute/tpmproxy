package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"

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
		&interceptor{})
	if err := relay.Relay(); err != nil {
		fmt.Printf("error: %v\n", err)
	}
}

type interceptor struct {
}

func (it *interceptor) HandleRequest(request *tpmproxy.Request) []byte {
	return request.Raw
}

func (it *interceptor) HandleResponse(request *tpmproxy.Request, response []byte) []byte {
	p := tpmproxy.RoughParser{
		RawRequest:  request.Raw,
		RawResponse: response,
	}
	switch request.Hdr.CommandCode {
	case tpm2.TPMCCUnseal:
		cmd := tpm2.Unseal{}
		resp := tpm2.UnsealResponse{}
		p.Cmd = &cmd
		p.Rsp = &resp
		if err := p.Parse(); err == nil {
			fmt.Printf("Unseal: %+v\n", cmd)
			fmt.Printf("UnsealResponse: %s\n", hex.EncodeToString(resp.OutData.Buffer))
		}
	case tpm2.TPMCCCreatePrimary:
		cmd := tpm2.CreatePrimary{}
		resp := tpm2.CreatePrimaryResponse{}
		p.Cmd = &cmd
		p.Rsp = &resp
		if err := p.Parse(); err == nil {
			fmt.Printf("CreatePrimary: %+v\n", cmd)
			fmt.Printf("CreatePrimaryResponse: %+v\n", resp)
		}
	case tpm2.TPMCCCreate:
		cmd := tpm2.Create{}
		resp := tpm2.CreateResponse{}
		p.Cmd = &cmd
		p.Rsp = &resp
		if err := p.Parse(); err == nil {
			//fmt.Printf("Create: %+v\n", cmd) // can't parse now
			fmt.Printf("CreateResponse: %+v\n", resp)
		}
	case tpm2.TPMCCNVReadPublic:
		cmd := tpm2.NVReadPublic{}
		resp := tpm2.NVReadPublicResponse{}
		p.Cmd = &cmd
		p.Rsp = &resp
		if err := p.Parse(); err == nil {
			fmt.Printf("NVReadPublic: %+v\n", cmd)
			fmt.Printf("NVReadPublicResponse: %+v\n", resp)
		}
	case tpm2.TPMCCNVRead:
		cmd := tpm2.NVRead{}
		resp := tpm2.NVReadResponse{}
		p.Cmd = &cmd
		p.Rsp = &resp
		if err := p.Parse(); err == nil {
			fmt.Printf("NVRead: %+v\n", cmd)
			fmt.Printf("NVReadResponse: %s\n", hex.EncodeToString(resp.Data.Buffer))
		}
	}
	return response
}
