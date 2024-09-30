package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/CyberDefenseInstitute/tpmproxy"
	"github.com/google/go-tpm/tpm2"
)

var (
	devName   string
	tpmPath   string
	relayAddr string
)

func main() {
	flag.StringVar(&devName, "name", "ctpm0", "cuse device name")
	flag.StringVar(&tpmPath, "tpm", "/dev/tpmrm0", "pass-through tpm device path")
	flag.StringVar(&relayAddr, "relayaddr", "127.0.0.1:2321", "internal relay address(for packet capture)")
	flag.Parse()

	// log.SetFlags(log.Lmicroseconds)
	tpmForwarderFactory := tpmproxy.NewIoForwarderFactory(tpmPath)
	tcpRelay := tpmproxy.NewTcpRelayer(relayAddr, tpmForwarderFactory, &interceptor{})
	go func() {
		if err := tcpRelay.Relay(); err != nil {
			fmt.Printf("tcp relay failed %v\n", err)
		}
	}()

	time.Sleep(100 * time.Millisecond) // wait for relay to start

	tcpForwarder, err := net.Dial("tcp", relayAddr)
	if err != nil {
		fmt.Printf("tcp forwarder open failed %v\n", err)
		return
	}
	defer tcpForwarder.Close()

	tpmproxy.SetCuseForwarder(tcpForwarder)
	code := tpmproxy.CuseRelay(devName)

	fmt.Printf("cuse relay exited: %d\n", code)
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
