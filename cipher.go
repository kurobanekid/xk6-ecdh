package xk6_ecdh

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

const (
	AesNonceSize = 16 // bytes
)

func AesGcmEncryptWithNonce(key []byte, plaintext string, nonce []byte) (ciphertext []byte) {
	plaintextBytes := []byte(plaintext)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesGcm, err := cipher.NewGCMWithNonceSize(block, AesNonceSize)
	if err != nil {
		panic(err.Error())
	}

	ciphertext = aesGcm.Seal(nil, nonce, plaintextBytes, nil)

	return
}

// AesGcmDecrypt takes a decryption key, a ciphertext and the corresponding nonce and decrypts it with AES256 in GCM mode. Returns the plaintext string.
func AesGcmDecrypt(key, ciphertext, nonce []byte) (plaintext []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesGcm, err := cipher.NewGCMWithNonceSize(block, AesNonceSize)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err = aesGcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return
}

func StrByXOR2Hex(k1 string, k2 string) ([]byte, error) {
	var retBytes []byte
	k1Len := len(k1)
	k2Len := len(k2)
	if k1Len != k2Len {
		return retBytes, errors.New("k1 and k2 length not equal")
	}

	for i := 0; i < k1Len; i++ {
		retBytes = append(retBytes, k1[i]^k2[i])
	}
	//return hex.EncodeToString(retBytes), nil
	return retBytes, nil
}
