package crypter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

/*
A Crypter object wraps an AES-SHA256 authenticated encryption
implementation.

Once created, Encrypt and Decrypt can be used with arbitrary data,
and will be padded, encrypted, and authenticated automatically.

Additionally, the Encode and Decode varients wrap the process in 
Base64 for string convinience.
*/
type Crypter struct {
	blockKey  []byte
	macKey    []byte
	iv        []byte
	encrypter cipher.BlockMode
	decrypter cipher.BlockMode
}

// Creates a new crypt block
func NewCrypter(blockKey, macKey, iv []byte) (*Crypter, error) {

	// check the aes key length
	switch len(blockKey) {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("Invalid blockKey size")
	}

	var c Crypter

	// create the aes cipher
	aesCipher, err := aes.NewCipher(blockKey)
	if err != nil {
		return nil, err
	}

	if len(iv) != aesCipher.BlockSize() {
		return nil, fmt.Errorf("Invalid IV size")
	}

	// init CBC block mode
	c.encrypter = cipher.NewCBCEncrypter(aesCipher, iv)
	c.decrypter = cipher.NewCBCDecrypter(aesCipher, iv)

	return &c, nil
}

// Encrypts data, then Base64 encodes it to a string
func (c *Crypter) EncryptEncode(data []byte) (string, error) {

	ciphertext, err := c.Encrypt(data)
	if err != nil {
		return "", err
	}

	return base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

// Encrypts data, and appends a HMAC for verification
func (c *Crypter) Encrypt(data []byte) ([]byte, error) {

	// copy to not overwrite original
	ciphertext := make([]byte, len(data))
	copy(ciphertext, data)

	// append padding
	padded, err := pkcs7Pad(ciphertext, c.encrypter.BlockSize())
	if err != nil {
		return nil, err
	}

	// Encrypt the data
	c.encrypter.CryptBlocks(padded, padded)

	// add the HMAC
	mac := hmac.New(sha256.New, c.macKey)
	mac.Write(padded)
	padded = mac.Sum(padded)

	// done
	return padded, nil
}

// Base64 decodes string, then decrypts
func (c *Crypter) DecryptDecode(data string) ([]byte, error) {

	decoded, err := base64.RawStdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	return c.Decrypt(decoded)
}

// Verify HMAC and decrypt data
func (c *Crypter) Decrypt(data []byte) ([]byte, error) {

	// copy to not overwrite
	ciphertext := make([]byte, len(data))
	copy(ciphertext, data)

	// check HMAC
	mac := hmac.New(sha256.New, c.macKey)
	dataLen := len(ciphertext) - mac.Size()
	mac.Write(ciphertext[:dataLen])
	expectedMac := mac.Sum(nil)

	if !hmac.Equal(ciphertext[dataLen:], expectedMac) {
		return nil, fmt.Errorf("HMAC Verification failure")
	}

	// Decrypt the data
	c.decrypter.CryptBlocks(ciphertext[:dataLen], ciphertext[:dataLen])

	// unpad
	unpadded, err := pkcs7Unpad(ciphertext[:dataLen], c.decrypter.BlockSize())
	if err != nil {
		return nil, err
	}

	// done
	return unpadded, nil
}

// Appends padding.
func pkcs7Pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	padlen := 1
	for ((len(data) + padlen) % blocklen) != 0 {
		padlen = padlen + 1
	}

	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}

// Returns slice of the original data without padding.
func pkcs7Unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}
	padlen := int(data[len(data)-1])
	if padlen > blocklen || padlen == 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	// check padding
	pad := data[len(data)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-padlen], nil
}
