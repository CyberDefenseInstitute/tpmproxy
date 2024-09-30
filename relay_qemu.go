package tpmproxy

import (
	"errors"
	"log"
	"net"
	"os"

	"github.com/opencontainers/runc/libcontainer/utils"
)

// QemuCtrlRelayer is a relayer for the UNIXIO control channel of QEMU.
// It listens on a UNIX domain socket for incoming connections from QEMU.
// Upon receiving a connection, it creates a pair of forwarders for the
// control channel and the server channel, and starts exchanging messages
// between the two channels.
// The relayer can be configured to terminate upon closing of either channel.
// The relayer can also be configured with an interceptor to intercept and
// modify messages.
type QemuCtrlRelayer struct {
	CtrlSockFile         string
	ForwarderFactory     ForwarderFactory
	CtrlForwarderFactory ForwarderFactory
	TerminateOnClose     bool
	Interceptor          Interceptor
	Terminate            chan interface{}
}

func NewQemuCtrlRelayer(ctrlSockFile string,
	forwarderFactory ForwarderFactory, ctrlForwarderFactory ForwarderFactory,
	terminateOnClose bool, interceptor Interceptor) *QemuCtrlRelayer {
	return &QemuCtrlRelayer{
		CtrlSockFile:         ctrlSockFile,
		ForwarderFactory:     forwarderFactory,
		CtrlForwarderFactory: ctrlForwarderFactory,
		TerminateOnClose:     terminateOnClose,
		Interceptor:          interceptor,
		Terminate:            make(chan interface{}),
	}
}

func (r *QemuCtrlRelayer) HandleConnLoop(qemuCtrlConn net.Conn) error {
	qemuCtrlUnixConn, ok := qemuCtrlConn.(*net.UnixConn)
	if !ok {
		return errors.New("not a unix conn")
	}
	qemuCtrlUnixFile, err := qemuCtrlUnixConn.File()
	if err != nil {
		return err
	}

	qemuServerFd, err := utils.RecvFd(qemuCtrlUnixFile)
	if err != nil {
		return err
	}

	if _, err := qemuCtrlConn.Write([]byte{0x00, 0x00, 0x00, 0x00}); err != nil {
		return err
	}

	fwd, err := r.ForwarderFactory.NewForwarder()
	if err != nil {
		return err
	}

	ctrlFwd, err := r.CtrlForwarderFactory.NewForwarder()
	if err != nil {
		return err
	}

	go func(qemuServerFd *os.File, fwd Forwarder) {
		defer fwd.Close()
		defer qemuServerFd.Close()

		var handlerFactory RequestResponseHandlerFactory
		if r.Interceptor != nil {
			handlerFactory = &TpmRequestResponseHandlerFactory{
				Interceptor: r.Interceptor,
			}
		} else {
			handlerFactory = &NopRequestResponseHandlerFactory{}
		}

		ex := &Exchanger{
			Src:            qemuServerFd,
			Dst:            fwd,
			HandlerFactory: handlerFactory,
		}
		if err := ex.Exchange(); err != nil {
			log.Printf("server exchange error: %v\n", err)
		}
		if r.TerminateOnClose {
			r.Terminate <- nil
		}
	}(qemuServerFd, fwd)

	go func(qemuCtrlConn net.Conn, ctrlFwd Forwarder) {
		defer ctrlFwd.Close()
		defer qemuCtrlConn.Close()
		ex := &Exchanger{
			Src:            qemuCtrlConn,
			Dst:            ctrlFwd,
			HandlerFactory: &NopRequestResponseHandlerFactory{},
		}
		if err := ex.Exchange(); err != nil {
			log.Printf("ctrl exchange error: %v\n", err)
		}
		if r.TerminateOnClose {
			r.Terminate <- nil
		}
	}(qemuCtrlConn, ctrlFwd)

	return nil
}

func (r *QemuCtrlRelayer) Relay() error {
	os.Remove(r.CtrlSockFile)

	listener, err := net.Listen("unix", r.CtrlSockFile)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	if err := os.Chmod(r.CtrlSockFile, 0666); err != nil {
		return err
	}

	newConns := make(chan net.Conn)
	go func() {
		for {
			newConn, err := listener.Accept()
			if err != nil {
				newConns <- nil
				r.Terminate <- nil
				return
			}
			newConns <- newConn
		}
	}()

	for {
		select {
		case conn := <-newConns:
			r.HandleConnLoop(conn)
		case <-r.Terminate:
			return nil
		}
	}
}
