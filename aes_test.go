package aes

import "testing"

func TestAES_Encrypt(t *testing.T) {
	tool := New(&Options{
		Mode:    CBCMode,
		Padding: PKCS7Padding,
		Output:  Base64Output,
		Key:     []byte("12345678123456781234567812345678"),
		IV:      []byte("1234567812345678"),
	})

	s, err := tool.Encrypt("this is content")
	if err != nil {
		t.Error(err)
	}
	if s != "pe4jT1kBKVWAiVoiv+XFbw==" {
		t.Error("encrypt result is error")
	}
}

func TestAES_Decrypt(t *testing.T) {
	tool := New(&Options{
		Mode:    CBCMode,
		Padding: PKCS7Padding,
		Output:  Base64Output,
		Key:     []byte("12345678123456781234567812345678"),
		IV:      []byte("1234567812345678"),
	})

	s, err := tool.Decrypt("pe4jT1kBKVWAiVoiv+XFbw==")
	if err != nil {
		t.Error(err)
	}
	if s != "this is content" {
		t.Error("decrypt result is error")
	}
}

func BenchmarkAES_Encrypt(b *testing.B) {
	tool := New(&Options{
		Mode:    CBCMode,
		Padding: PKCS7Padding,
		Output:  Base64Output,
		Key:     []byte("12345678123456781234567812345678"),
		IV:      []byte("1234567812345678"),
	})
	for i := 0; i < b.N; i++ {
		_, err := tool.Encrypt("this is content")
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkAES_Decrypt(b *testing.B) {
	tool := New(&Options{
		Mode:    CBCMode,
		Padding: PKCS7Padding,
		Output:  Base64Output,
		Key:     []byte("12345678123456781234567812345678"),
		IV:      []byte("1234567812345678"),
	})
	for i := 0; i < b.N; i++ {
		_, err := tool.Decrypt("pe4jT1kBKVWAiVoiv+XFbw==")
		if err != nil {
			b.Error(err)
		}
	}
}
