package tpmproxy

import (
	"io"
)

// Exchanger is a struct that exchanges data between two io.ReadWriters.
// It uses a RequestResponseHandlerFactory to create RequestResponseHandlers
// for each request-response pair.
type Exchanger struct {
	// Src is the exchange source.
	Src io.ReadWriter
	// Dst is the exchange destination.
	Dst io.ReadWriter
	// HandlerFactory is the factory that creates RequestResponseHandlers.
	HandlerFactory RequestResponseHandlerFactory
}

// Exchange exchanges data between the source and destination.
func (ex *Exchanger) Exchange() error {
	reqBuf := make([]byte, 4096)
	respBuf := make([]byte, 4096)
	for {
		handler := ex.HandlerFactory.NewRequestResponseHandler()

		requestLen, err := ex.Src.Read(reqBuf)
		if err != nil {
			return FilterClosedErr(err)
		}
		request := reqBuf[:requestLen]
		request = handler.HandleRequest(request)
		// log.Printf("request: %s\n", hex.EncodeToString(request))

		if _, err := ex.Dst.Write(request); err != nil {
			return FilterClosedErr(err)
		}

		responseLen, err := ex.Dst.Read(respBuf)
		if err != nil {
			return FilterClosedErr(err)
		}
		response := respBuf[:responseLen]
		response = handler.HandleResponse(response)
		// log.Printf("response: %s\n", hex.EncodeToString(response))

		if _, err := ex.Src.Write(response); err != nil {
			return FilterClosedErr(err)
		}
	}
}
