package xk6_ecdh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go.k6.io/k6/js/modules"
	"math/big"
)

func init() {
	modules.Register("k6/x/ecdh", new(Ecdh))
}

type Ecdh struct {
}

type KeyPair struct {
	PrivX string `json:"privX"`
	PrivY string `json:"privY"`
	D     string `json:"d"`
	PubX  string `json:"pubX"`
	PubY  string `json:"pubY"`
}

type ComputeMaterial struct {
	//PrivX   string `json:"privX"`
	//PrivY   string `json:"privY"`
	D string `json:"d"`
	//PubX    string `json:"pubX"`
	//PubY    string `json:"pubY"`
	SrvPubX string `json:"srvPubX"`
	SrvPubY string `json:"srvPubY"`
}

func (e *Ecdh) GenerateKey() string {
	curve := elliptic.P256()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return ""
	}
	pub := &priv.PublicKey
	privX := fmt.Sprintf("%064x", priv.X)
	privY := fmt.Sprintf("%064x", priv.Y)
	d := fmt.Sprintf("%064x", priv.D)

	pubX := fmt.Sprintf("%064x", pub.X)
	pubY := fmt.Sprintf("%064x", pub.Y)

	keyPair := KeyPair{
		PrivX: privX,
		PrivY: privY,
		D:     d,
		PubX:  pubX,
		PubY:  pubY,
	}

	res, err := json.Marshal(keyPair)
	if err != nil {
		return ""
	}

	return string(res)
}

func (e *Ecdh) ComputeSharedSecret(material string) string {
	var input ComputeMaterial
	err := json.Unmarshal([]byte(material), &input)
	if err != nil {
		return ""
	}

	// transform string to bigint
	srvPubX := new(big.Int)
	srvPubX.SetString(input.SrvPubX, 16)
	SrvPubY := new(big.Int)
	SrvPubY.SetString(input.SrvPubY, 16)
	d := new(big.Int)
	d.SetString(input.D, 16)

	srvPub := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     srvPubX,
		Y:     SrvPubY,
	}

	x, _ := srvPub.Curve.ScalarMult(srvPubX, SrvPubY, d.Bytes())
	if err != nil {
		return ""
	}

	secretHex := fmt.Sprintf("%064x", x.Bytes())
	verify := fmt.Sprintf("%x", sha512.Sum512([]byte(secretHex)))

	return fmt.Sprintf("%s,%s", secretHex, verify)
}

// AesGcmEncrypt output base64 format string
func (e *Ecdh) AesGcmEncrypt(plaintext, keyHex, noncePrefix, nonceSuffix string) string {
	nonce, err := StrByXOR2Hex(noncePrefix, nonceSuffix)
	if err != nil {
		return ""
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return ""
	}
	fmt.Printf("key: %v\n", key)
	fmt.Printf("nonce: %v\n", nonce)
	fmt.Printf("plaintext: %v\n", plaintext)
	ciphertext := AesGcmEncryptWithNonce(key, plaintext, nonce)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)

	return ciphertextBase64
}

func (e *Ecdh) AesGcmDecrypt(ciphertextBase64, keyHex, noncePrefix, nonceSuffix string) string {
	nonce, err := StrByXOR2Hex(noncePrefix, nonceSuffix)
	if err != nil {
		return ""
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return ""
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return ""
	}

	plaintext := AesGcmDecrypt(key, ciphertext, nonce)
	//plaintextBase64 := base64.StdEncoding.EncodeToString(plaintext)

	return string(plaintext)
}
