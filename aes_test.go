package aes

import "testing"

var key = "1234567812345678"
var data = `{"id":100001,"name":"tom","age":20,"job":"teacher","address":"beijing China","admin":true,"created_at":"2000-01-01 00:00:00","updated_at":"2000-01-01 00:00:00"}`
var iv = "1234567812345678"

func testMode(t *testing.T, m Mode) {
	opts := NewOptions([]byte(key), []byte(iv))
	opts.Mode = m
	tool := New(opts)

	s, err := tool.Encrypt(data)
	if err != nil {
		t.Error(err)
	}
	raw, err := tool.Decrypt(s)
	if err != nil {
		t.Error(err)
	}
	if data != raw {
		t.Error("mode is error")
	}
}

func TestECB(t *testing.T) {
	testMode(t, ECBMode)
}

func TestCBC(t *testing.T) {
	testMode(t, CBCMode)
}

func TestCTR(t *testing.T) {
	testMode(t, CTRMode)
}

func TestOFB(t *testing.T) {
	testMode(t, OFBMode)
}

func TestCFB(t *testing.T) {
	testMode(t, CFBMode)
}
