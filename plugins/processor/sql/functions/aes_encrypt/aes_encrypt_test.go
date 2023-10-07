package aes_encrypt

import (
	"testing"
)

func TestAes_encrypt(t *testing.T) {
	key := "0000000000000000000000000000000000000000000000000000000000000000"
	// iv := "00000000000000000000000000000000"
	aesEncrypt := &Aes_encrypt{}
	if err := aesEncrypt.Init("aes_encrypt", key); err != nil {
		t.Errorf("Failed to initialize Aes_encrypt: %v", err)
	}

	// Test case 1: encrypt a string
	plaintext := "0123456"
	expectedCiphertext := "bc3acdbd40c283d91f7dc7010fd7d2b1"
	ciphertext, err := aesEncrypt.Process(plaintext, key)
	if err != nil {
		t.Errorf("Failed to encrypt plaintext: %v", err)
	}
	if ciphertext != expectedCiphertext {
		t.Errorf("Encryption failed. Expected: %v, got: %v", expectedCiphertext, ciphertext)
	}

	// // Test case 2: encrypt an empty string
	// plaintext = ""
	// expectedCiphertext = "d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5"
	// ciphertext, err = aesEncrypt.Process(plaintext, key)
	// if err != nil {
	// 	t.Errorf("Failed to encrypt plaintext: %v", err)
	// }
	// if ciphertext != expectedCiphertext {
	// 	t.Errorf("Encryption failed. Expected: %v, got: %v", expectedCiphertext, ciphertext)
	// }

	// // Test case 3: encrypt a string with a null character
	// plaintext = "hello\x00world"
	// expectedCiphertext = "f7d1f3d4c8f5d8e5d8f5d8e5d8f5d8e5"
	// ciphertext, err = aesEncrypt.Process(plaintext, key)
	// if err != nil {
	// 	t.Errorf("Failed to encrypt plaintext: %v", err)
	// }
	// if ciphertext != expectedCiphertext {
	// 	t.Errorf("Encryption failed. Expected: %v, got: %v", expectedCiphertext, ciphertext)
	// }

	// Test case 4: encrypt a null string
	plaintext = "NULL"
	expectedCiphertext = "NULL"
	ciphertext, err = aesEncrypt.Process(plaintext, key)
	if err != nil {
		t.Errorf("Failed to encrypt plaintext: %v", err)
	}
	if ciphertext != expectedCiphertext {
		t.Errorf("Encryption failed. Expected: %v, got: %v", expectedCiphertext, ciphertext)
	}

	// Test case 5: encrypt with incorrect number of parameters
	_, err = aesEncrypt.Process("hello")
	if err == nil {
		t.Errorf("Expected error for incorrect number of parameters")
	}
}
