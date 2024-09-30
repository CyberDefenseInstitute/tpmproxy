package tpmproxy

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestGetCapability(t *testing.T) {
	rawReq, _ := hex.DecodeString("8001000000160000017a00000006000001000000007f")
	rawResp, _ := hex.DecodeString("8001000001830000000000000000060000002e00000100322e3000000001010000000000000102000000a4000001030000004b00000104000007e50000010549424d000000010653572020000001072054504d000001080000000000000109000000000000010a000000010000010b201910230000010c001636360000010d000004000000010e000000030000010f000000070000011000000003000001110000004000000112000000180000011300000003000001140000ffff00000116000000000000011700000800000001180000000600000119000010000000011a0000000d0000011b000000060000011c000001000000011d000000ff0000011e000010000000011f0000100000000120000000400000012100000a84000001220000019400000123322e3000000001240000000000000125000000a4000001260000004b00000127000007e50000012800000080000001290000006e0000012a0000006e0000012b000000000000012c000004000000012d000000000000012e00000400")

	cmd := tpm2.GetCapability{}
	resp := tpm2.GetCapabilityResponse{}

	p := RoughParser{
		RawRequest:  rawReq,
		RawResponse: rawResp,
		Cmd:         &cmd,
		Rsp:         &resp,
	}
	if err := p.Parse(); err != nil {
		t.Error(err)
		return
	}

	t.Logf("%+v", cmd)
	t.Logf("%+v", resp)

	{
		var buf bytes.Buffer
		buf.Write(rawResp[:p.RspParameterOffset])
		if err := Marshal(&buf, reflect.ValueOf(resp.MoreData)); err != nil {
			t.Error(err)
			return
		}
		if err := Marshal(&buf, reflect.ValueOf(resp.CapabilityData)); err != nil {
			t.Error(err)
			return
		}
		t.Logf("%x", buf.Bytes())
	}

	props, err := resp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return
	}
	for idx := range props.TPMProperty {
		prop := &props.TPMProperty[idx]
		if prop.Property == tpm2.TPMPTManufacturer {
			fmt.Printf("prop(bfr): %+x\n", prop.Value)
			prop.Value = 0xdeadbeef
			fmt.Printf("prop(aft): %+x\n", prop.Value)
		}
	}

	{
		var buf2 bytes.Buffer
		buf2.Write(rawResp[:p.RspParameterOffset])
		if err := Marshal(&buf2, reflect.ValueOf(resp.MoreData)); err != nil {
			t.Error(err)
			return
		}
		if err := Marshal(&buf2, reflect.ValueOf(resp.CapabilityData)); err != nil {
			t.Error(err)
			return
		}
		t.Logf("%x", buf2.Bytes())
	}
}
