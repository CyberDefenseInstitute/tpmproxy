package tpmproxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	_ "unsafe"

	"github.com/google/go-tpm/tpm2"
)

//go:linkname rspHeader github.com/google/go-tpm/tpm2.rspHeader
func rspHeader(rsp *bytes.Buffer) error
func RspHeader(rsp *bytes.Buffer) error {
	return rspHeader(rsp)
}

//go:linkname rspHandles github.com/google/go-tpm/tpm2.rspHandles
func rspHandles(rsp *bytes.Buffer, rspStruct any) error
func RspHandles(rsp *bytes.Buffer, rspStruct any) error {
	return rspHandles(rsp, rspStruct)
}

//go:linkname rspParametersArea github.com/google/go-tpm/tpm2.rspParametersArea
func rspParametersArea(hasSessions bool, rsp *bytes.Buffer) ([]byte, error)
func RspParametersArea(hasSessions bool, rsp *bytes.Buffer) ([]byte, error) {
	return rspParametersArea(hasSessions, rsp)
}

//go:linkname rspSessions github.com/google/go-tpm/tpm2.rspSessions
func rspSessions(rsp *bytes.Buffer, rc tpm2.TPMRC, cc tpm2.TPMCC, names []tpm2.TPM2BName, parms []byte, sess []tpm2.Session) error
func RspSessions(rsp *bytes.Buffer, rc tpm2.TPMRC, cc tpm2.TPMCC, names []tpm2.TPM2BName, parms []byte, sess []tpm2.Session) error {
	return rspSessions(rsp, rc, cc, names, parms, sess)
}

//go:linkname rspParameters github.com/google/go-tpm/tpm2.rspParameters
func rspParameters(parms []byte, sess []tpm2.Session, rspStruct any) error
func RspParameters(parms []byte, sess []tpm2.Session, rspStruct any) error {
	return rspParameters(parms, sess, rspStruct)
}

//go:linkname taggedMembers github.com/google/go-tpm/tpm2.taggedMembers
func taggedMembers(v reflect.Value, tag string, invert bool) []reflect.Value
func TaggedMembers(v reflect.Value, tag string, invert bool) []reflect.Value {
	return taggedMembers(v, tag, invert)
}

//go:linkname unmarshal github.com/google/go-tpm/tpm2.unmarshal
func unmarshal(buf *bytes.Buffer, v reflect.Value) error
func Unmarshal(buf *bytes.Buffer, v reflect.Value) error {
	return unmarshal(buf, v)
}

//go:linkname hasTag github.com/google/go-tpm/tpm2.hasTag
func hasTag(t reflect.StructField, query string) bool
func HasTag(t reflect.StructField, query string) bool {
	return hasTag(t, query)
}

//go:linkname isMarshalledByReflection github.com/google/go-tpm/tpm2.isMarshalledByReflection
func isMarshalledByReflection(v reflect.Value) bool
func IsMarshalledByReflection(v reflect.Value) bool {
	return isMarshalledByReflection(v)
}

//go:linkname marshal github.com/google/go-tpm/tpm2.marshal
func marshal(buf *bytes.Buffer, v reflect.Value) error
func Marshal(buf *bytes.Buffer, v reflect.Value) error {
	return marshal(buf, v)
}

func ReqHeader(req *bytes.Buffer) (*tpm2.TPMCmdHeader, error) {
	var hdr tpm2.TPMCmdHeader
	if err := unmarshal(req, reflect.ValueOf(&hdr).Elem()); err != nil {
		return nil, fmt.Errorf("unmarshalling TPM request: %w", err)
	}
	return &hdr, nil
}

func ReqHandles(req *bytes.Buffer, cmd any) error {
	v := reflect.ValueOf(cmd).Elem()
	tag := "handle"
	invert := false

	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		if hasTag(t.Field(i), tag) != invert {
			var h tpm2.TPMHandle
			if err := binary.Read(req, binary.BigEndian, &h); err != nil {
				return fmt.Errorf("unmarshalling handle %v: %w", i, err)
			}
			v.Field(i).Set(reflect.ValueOf(h))
		}
	}

	return nil
}

func ReqParameters(req *bytes.Buffer, sess []tpm2.Session, cmd any, rh *tpm2.TPMCmdHeader) error {
	if req.Len() == 0 {
		return nil
	}

	switch rh.CommandCode {
	default:
		numHandles := len(taggedMembers(reflect.ValueOf(cmd).Elem(), "handle", false))
		for i := numHandles; i < reflect.TypeOf(cmd).Elem().NumField(); i++ {
			parmsField := reflect.ValueOf(cmd).Elem().Field(i)
			if parmsField.Kind() == reflect.Ptr && hasTag(reflect.TypeOf(cmd).Elem().Field(i), "optional") {
				if binary.BigEndian.Uint16(req.Bytes()) == 0 {
					req.Next(2)
					continue
				}
			}
			if isMarshalledByReflection(parmsField) {
				if err := unmarshal(req, parmsField); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// RoughParser is a rough parser for TPM commands and responses.
// It parses the raw request and response buffers and populates the
// provided command and response structures.
// The command and response structures must be pointers to the
// corresponding command and response structures.
// It also holds the offsets of the command and response parameters
// as the parsing results.
// The offsets are useful for building request and response after
// parameter tampering.
type RoughParser struct {
	RawRequest  []byte
	RawResponse []byte

	// Cmd is the command structure pointer
	Cmd any
	// Rsp is the response structure pointer
	Rsp    any
	CmdHdr *tpm2.TPMCmdHeader

	// CmdParameterOffset is the offset of the command parameters
	CmdParameterOffset int
	// RspParameterOffset is the offset of the response parameters
	RspParameterOffset int
}

func (p *RoughParser) Parse() error {
	reqBuf := bytes.NewBuffer(p.RawRequest)
	rh, err := ReqHeader(reqBuf)
	if err != nil {
		return err
	}
	p.CmdHdr = rh

	hasSessions := false
	sess := []tpm2.Session{}

	switch rh.Tag {
	case tpm2.TPMSTSessions:
		hasSessions = true
	case tpm2.TPMSTNoSessions:
	}

	if err := ReqHandles(reqBuf, p.Cmd); err != nil {
		return err
	}

	if hasSessions {
		var authAreaSize uint32
		if err := binary.Read(reqBuf, binary.BigEndian, &authAreaSize); err != nil {
			return fmt.Errorf("unmarshalling auth area size: %w", err)
		}
		auth := make([]byte, authAreaSize)
		if err := binary.Read(reqBuf, binary.BigEndian, auth); err != nil {
			return fmt.Errorf("unmarshalling auth area: %w", err)
		}
	}

	p.CmdParameterOffset = len(p.RawRequest) - reqBuf.Len()
	if err := ReqParameters(reqBuf, sess, p.Cmd, rh); err != nil {
		// ignore the error for now
		// return err
	}

	rspBuf := bytes.NewBuffer(p.RawResponse)
	if err := rspHeader(rspBuf); err != nil {
		return err
	}
	if err = rspHandles(rspBuf, p.Rsp); err != nil {
		return err
	}

	p.RspParameterOffset = len(p.RawResponse) - rspBuf.Len()
	rspParms, err := rspParametersArea(hasSessions, rspBuf)
	if err != nil {
		return err
	}
	// if hasSessions {
	// 	// We don't need the TPM RC here because we would have errored
	// 	// out from rspHeader
	// 	// TODO: Authenticate the error code with sessions, if desired.
	// 	err = rspSessions(rspBuf, tpm2.TPMRCSuccess, cc, names, rspParms, sess)
	// 	if err != nil {
	// 		return err
	// 	}
	// }
	if err := rspParameters(rspParms, sess, p.Rsp); err != nil {
		return err
	}

	return nil
}
