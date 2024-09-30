package tpmproxy

import "bytes"

// RequestResponseHandler is an interface that handles request-response pairs.
type RequestResponseHandler interface {
	// HandleRequest handles a request and returns a modified request.
	// The request is a byte slice that contains the raw request.
	HandleRequest(request []byte) []byte
	// HandleResponse handles a response and returns a modified response.
	// The response is a byte slice that contains the raw response.
	HandleResponse(response []byte) []byte
}

// RequestResponseHandlerFactory is an interface that creates RequestResponseHandlers.
type RequestResponseHandlerFactory interface {
	// NewRequestResponseHandler creates a new RequestResponseHandler.
	NewRequestResponseHandler() RequestResponseHandler
}

// NopRequestResponseHandler is a RequestResponseHandler that does nothing.
type NopRequestResponseHandler struct {
}

func (h *NopRequestResponseHandler) HandleRequest(request []byte) []byte {
	return request
}

func (h *NopRequestResponseHandler) HandleResponse(response []byte) []byte {
	return response
}

// NopRequestResponseHandlerFactory is a RequestResponseHandlerFactory that creates NopRequestResponseHandlers.
type NopRequestResponseHandlerFactory struct {
	Handler NopRequestResponseHandler
}

func (f *NopRequestResponseHandlerFactory) NewRequestResponseHandler() RequestResponseHandler {
	return &f.Handler
}

// TpmRequestResponseHandlerFactory is a RequestResponseHandlerFactory that creates TpmRequestResponseHandlers.
type TpmRequestResponseHandlerFactory struct {
	// Interceptor is the Interceptor that intercepts requests and responses.
	Interceptor Interceptor
}

func (f *TpmRequestResponseHandlerFactory) NewRequestResponseHandler() RequestResponseHandler {
	return &TpmRequestResponseHandler{
		Interceptor: f.Interceptor,
	}
}

// TpmRequestResponseHandler is a RequestResponseHandler that handles TPM request-response pairs.
type TpmRequestResponseHandler struct {
	Interceptor Interceptor
	Request     Request
}

// HandleRequest handles a request and returns a Interceptor-modified request.
func (h *TpmRequestResponseHandler) HandleRequest(request []byte) []byte {
	h.Request.Raw = request
	if len(request) < 10 /* sizeof(TPMCmdHeader) */ {
		return request
	}

	var err error
	reqBuf := bytes.NewBuffer(request)
	if h.Request.Hdr, err = ReqHeader(reqBuf); err != nil {
		return request
	}

	return h.Interceptor.HandleRequest(&h.Request)
}

// HandleResponse handles a response and returns a Interceptor-modified response.
func (h *TpmRequestResponseHandler) HandleResponse(response []byte) []byte {
	return h.Interceptor.HandleResponse(&h.Request, response)
}
