package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"testing"
)

func TestCreateKey(t *testing.T) {
	tpm, err := OpenRealTPM()
	defer tpm.Close()

	if err != nil {
		t.Errorf("%v", err)
	}

	handle, keyP, err := tpm.CreateKey()

	if err != nil {
		t.Errorf("%v", err)
	}

	fmt.Printf("handle: %v\n", handle)
	fmt.Printf("key public key: %v\n", keyP)
}

func TestReadEKCert(t *testing.T) {
	tpm, err := OpenRealTPM()
	defer tpm.Close()

	if err != nil {
		t.Errorf("%v", err)
	}

	cert, err := tpm.ReadEKCert()

	if err != nil {
		t.Errorf("%v", err)
	}

	if cert.PublicKeyAlgorithm != x509.RSA {
		t.Errorf("algorism is worng: %v", cert.PublicKeyAlgorithm)
	}
}

func TestActivateCredential(t *testing.T) {
	tpm, err := OpenRealTPM()
	defer tpm.Close()

	credential := []byte("hello")
	encCred := make([]byte, len(credential))

	if err != nil {
		t.Errorf("%v", err)
	}

	cert, err := tpm.ReadEKCert()

	if err != nil {
		t.Errorf("%v", err)
	}

	pubkey := cert.PublicKey.(*rsa.PublicKey)

	seedHash := sha256.New()

	secret, err := rsa.EncryptOAEP(seedHash, rand.Reader, pubkey, []byte("seed"), []byte(""))
	if err != nil {
		t.Errorf("%v", err)
	}

	secretCipher, err := aes.NewCipher(secret[:32])

	if err != nil {
		t.Errorf("%v", err)
	}

	secretCFBEncrypter := cipher.NewCFBEncrypter(secretCipher, []byte("aaaaaaaaaaaaaaaa"))
	secretCFBEncrypter.XORKeyStream(encCred, credential)

	fmt.Printf("%v", secret)
}
