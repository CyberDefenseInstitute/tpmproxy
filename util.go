package tpmproxy

import (
	"errors"
	"io"
	"net"
	"syscall"
)

func FilterClosedErr(err error) error {
	switch {
	case
		errors.Is(err, net.ErrClosed),
		errors.Is(err, io.EOF),
		errors.Is(err, syscall.EPIPE):
		return nil
	default:
		return err
	}
}
