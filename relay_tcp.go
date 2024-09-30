package tpmproxy

import (
	"fmt"
	"net"
)

// TcpRelayer is a relayer for TCP connections.
// TcpRelayer is used to turn non-network traffic into network traffic so that it can be captured.
type TcpRelayer struct {
	Addr             string
	ForwarderFactory ForwarderFactory
	TerminateOnClose bool
	Interceptor      Interceptor
	Terminate        chan interface{}
}

func NewTcpRelayer(addr string, forwarderFactory ForwarderFactory, interceptor Interceptor) *TcpRelayer {
	return &TcpRelayer{
		Addr:             addr,
		ForwarderFactory: forwarderFactory,
		Interceptor:      interceptor,
		Terminate:        make(chan interface{}),
	}
}

func (r *TcpRelayer) Relay() error {
	listener, err := net.Listen("tcp", r.Addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	newConns := make(chan net.Conn)
	go func() {
		for {
			newConn, err := listener.Accept()
			if err != nil {
				newConns <- nil
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

func (r *TcpRelayer) HandleConnLoop(conn net.Conn) error {
	fwd, err := r.ForwarderFactory.NewForwarder()
	if err != nil {
		return err
	}

	go func(conn net.Conn, fwd Forwarder) {
		defer fwd.Close()
		defer conn.Close()

		var handlerFactory RequestResponseHandlerFactory
		if r.Interceptor != nil {
			handlerFactory = &TpmRequestResponseHandlerFactory{
				Interceptor: r.Interceptor,
			}
		} else {
			handlerFactory = &NopRequestResponseHandlerFactory{}
		}
		ex := &Exchanger{
			Src:            conn,
			Dst:            fwd,
			HandlerFactory: handlerFactory,
		}
		if err := ex.Exchange(); err != nil {
			fmt.Printf("exchange error: %v\n", err)
		}

		if r.TerminateOnClose {
			r.Terminate <- nil
		}
	}(conn, fwd)
	return nil
}
