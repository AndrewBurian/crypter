package crypter

import (
	"testing"
)

func Test16bPass(t *testing.T) {

	aesKey := []byte("1234567890123456")
	macKey := []byte("mackey")
	iv := []byte("1234567890123456")

	crypter, err := NewCrypter(aesKey, macKey, iv)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	original := []byte("This is a message to be encrypted")

	ciphertext, err := crypter.EncryptEncode(original)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	plaintext, err := crypter.DecryptDecode(ciphertext)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	if !testEq(original, plaintext) {
		t.Error("Original != decrypted")
		t.Errorf("Want: %v", original)
		t.Errorf("Got : %v", plaintext)
		t.FailNow()
	}
}

func Test24bPass(t *testing.T) {

	aesKey := []byte("123456789012345678901234")
	macKey := []byte("mackey")
	iv := []byte("1234567890123456")

	crypter, err := NewCrypter(aesKey, macKey, iv)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	original := []byte("This is a message to be encrypted")

	ciphertext, err := crypter.EncryptEncode(original)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	plaintext, err := crypter.DecryptDecode(ciphertext)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	if !testEq(original, plaintext) {
		t.Error("Original != decrypted")
		t.Errorf("Want: %v", original)
		t.Errorf("Got : %v", plaintext)
		t.FailNow()
	}
}

func Test32bPass(t *testing.T) {

	aesKey := []byte("12345678901234567890123456789012")
	macKey := []byte("mackey")
	iv := []byte("1234567890123456")

	crypter, err := NewCrypter(aesKey, macKey, iv)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	original := []byte("This is a message to be encrypted")

	ciphertext, err := crypter.EncryptEncode(original)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	plaintext, err := crypter.DecryptDecode(ciphertext)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	if !testEq(original, plaintext) {
		t.Error("Original != decrypted")
		t.Errorf("Want: %v", original)
		t.Errorf("Got : %v", plaintext)
		t.FailNow()
	}
}

func testEq(a, b []byte) bool {

	if a == nil && b == nil {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
