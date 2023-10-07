package aes_encrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/alibaba/ilogtail/plugins/processor/sql"
)

// aes_encrypt
type Aes_encrypt struct {
	cipher    cipher.Block
	blockSize int
	key       []byte
	iv        []byte
}

func (f *Aes_encrypt) Init(param ...string) error {
	if len(param) < 2 {
		return fmt.Errorf("aes_encrypt: need at least 2 parameters")
	}
	if err := f.parseKey(param[1]); err != nil {
		return err
	}
	if err := f.parseIV(); err != nil {
		return err
	}
	return nil
}

// if str or key_str is NULL, return NULL.
func (f *Aes_encrypt) Process(param ...string) (string, error) {
	if len(param) < 2 {
		return "", fmt.Errorf("aes_encrypt: need at least 2 parameters")
	}
	if param[0] == "NULL" || param[1] == "NULL" {
		return "NULL", nil
	}
	ciphertext, err := f.encrypt(param[0])
	if err == nil {
		return hex.EncodeToString(ciphertext), nil
	} else {
		return "", fmt.Errorf("encrypt field %v error: %v", param[0], err)
	}
}

func (f *Aes_encrypt) encrypt(plaintext string) ([]byte, error) {
	paddingData := f.paddingWithPKCS7(plaintext)
	var ciphertext []byte
	iv := f.iv
	if iv != nil {
		ciphertext = make([]byte, len(paddingData))
	} else {
		ciphertext = make([]byte, f.blockSize+len(paddingData))
		iv = ciphertext[:f.blockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, fmt.Errorf("construct IV error: %v", iv)
		}
	}

	mode := cipher.NewCBCEncrypter(f.cipher, iv)
	if f.iv != nil {
		mode.CryptBlocks(ciphertext, paddingData)
	} else {
		mode.CryptBlocks(ciphertext[f.blockSize:], paddingData)
	}
	return ciphertext, nil
}

func (f *Aes_encrypt) paddingWithPKCS7(data string) []byte {
	paddingSize := f.blockSize - len(data)%f.blockSize
	dataBytes := make([]byte, len(data)+paddingSize)
	copy(dataBytes, data)
	copy(dataBytes[len(data):], bytes.Repeat([]byte{byte(paddingSize)}, paddingSize))
	return dataBytes
}

func (f *Aes_encrypt) parseKey(key string) error {
	var err error
	// Decode from hex to bytes.
	if f.key, err = hex.DecodeString(key); err != nil {
		return fmt.Errorf("aes_encrypt decodes key from hex error: %v, try hex", err)
	}
	if f.cipher, err = aes.NewCipher(f.key); err != nil {
		return fmt.Errorf("aes_encrypt create cipher with key error: %v", err)
	}
	f.blockSize = f.cipher.BlockSize()
	return nil
}

func (f *Aes_encrypt) parseIV() error {
	iv := strings.Repeat("0", 16*2)
	var err error
	if f.iv, err = hex.DecodeString(iv); err != nil {
		return fmt.Errorf("aes_encrypt decodes IV %v error: %v", iv, err)
	}
	if len(f.iv) != f.blockSize {
		return fmt.Errorf("aes_encrypt finds size mismatch between IV(%v) and BlockSize(%v), must be same",
			len(f.iv), f.blockSize)
	}
	return nil
}

func (f *Aes_encrypt) Name() string {
	return "aes_encrypt"
}

func init() {
	sql.FunctionMap["aes_encrypt"] = func() sql.Function {
		return &Aes_encrypt{}
	}
}
