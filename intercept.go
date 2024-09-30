package tpmproxy

import (
	"github.com/google/go-tpm/tpm2"
)

// Request is a struct that contains a TPM command header and raw command.
type Request struct {
	// Hdr is the TPM command header.
	Hdr *tpm2.TPMCmdHeader
	// Raw is the raw command.
	Raw []byte
}

// Interceptor is an interface that intercepts requests and responses.
type Interceptor interface {
	// HandleRequest handles a request and returns a modified request.
	HandleRequest(request *Request) []byte
	// HandleResponse handles a response and returns a modified response.
	HandleResponse(request *Request, response []byte) []byte
}
