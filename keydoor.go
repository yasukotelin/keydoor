package keydoor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Keydoor is struct that provids the encrypting and decrypting functions
type Keydoor struct {
	Key   []byte
	block *cipher.Block
}

// NewKeydoor returns new Keydoor struct pointer.
// key is must 32 length. It is private key and must not publish it.
func NewKeydoor(key []byte) (*Keydoor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key length is %d but it is must 32 length", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &Keydoor{
		Key:   key,
		block: &block,
	}, nil
}

// Encrypt the plain text. This returns the encrypted new byte slice.
func (kd *Keydoor) Encrypt(plainText string) (encryptBytes []byte, err error) {
	encryptBytes = make([]byte, aes.BlockSize+len(plainText))
	iv := encryptBytes[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return encryptBytes, err
	}
	stream := cipher.NewCTR(*kd.block, iv)
	stream.XORKeyStream(encryptBytes[aes.BlockSize:], []byte(plainText))

	return encryptBytes, nil
}

// Decrypt the encrypted byte slice. And this returns the decrypted plain text.
func (kd *Keydoor) Decrypt(encryptBytes []byte) (string, error) {
	plainBytes := make([]byte, len(encryptBytes[aes.BlockSize:]))
	stream := cipher.NewCTR(*kd.block, encryptBytes[:aes.BlockSize])
	stream.XORKeyStream(plainBytes, encryptBytes[aes.BlockSize:])
	return string(plainBytes), nil
}
