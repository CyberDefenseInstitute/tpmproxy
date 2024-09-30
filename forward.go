package tpmproxy

import (
	"io"
	"net"
	"syscall"
)

// Forwarder is an interface that forwards data to a destination.
type Forwarder io.ReadWriteCloser

// ForwarderFactory is an interface that creates Forwarders.
type ForwarderFactory interface {
	NewForwarder() (Forwarder, error)
}

// TcpForwarderFactory is a ForwarderFactory that creates TCP Forwarders.
type TcpForwarderFactory struct {
	Addr string
}

// NewTcpForwarderFactory creates a new TcpForwarderFactory.
func NewTcpForwarderFactory(addr string) *TcpForwarderFactory {
	return &TcpForwarderFactory{
		Addr: addr,
	}
}

// NewForwarder creates a new TCP Forwarder.
func (f *TcpForwarderFactory) NewForwarder() (Forwarder, error) {
	return net.Dial("tcp", f.Addr)
}

// IoForwarderFactory is a ForwarderFactory that creates IO Forwarders.
type IoForwarderFactory struct {
	Path string
}

// IoForwarder is a Forwarder that forwards data to a file descriptor.
type IoForwarder struct {
	Fd int
}

func (f *IoForwarder) Read(p []byte) (int, error) {
	return syscall.Read(f.Fd, p)
}

func (f *IoForwarder) Write(p []byte) (int, error) {
	return syscall.Write(f.Fd, p)
}

func (f *IoForwarder) Close() error {
	return syscall.Close(f.Fd)
}

// NewIoForwarderFactory creates a new IoForwarderFactory.
func NewIoForwarderFactory(path string) *IoForwarderFactory {
	return &IoForwarderFactory{
		Path: path,
	}
}

// NewForwarder creates a new IO Forwarder.
func (f *IoForwarderFactory) NewForwarder() (Forwarder, error) {
	// return os.OpenFile(f.Path, os.O_RDWR, 0600) // It may behave like non-blocking IO.
	fd, err := syscall.Open(f.Path, syscall.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	return &IoForwarder{Fd: fd}, nil
}
