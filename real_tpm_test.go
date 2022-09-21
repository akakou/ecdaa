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

	legacy "github.com/google/go-tpm/legacy/tpm2"
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
	wrapedSecret := make([]byte, int(256))

	if err != nil {
		t.Errorf("%v", err)
	}

	cert, err := tpm.ReadEKCert()

	if err != nil {
		t.Errorf("%v", err)
	}

	pubkey := cert.PublicKey.(*rsa.PublicKey)

	seed := []byte("seed")

	seedHash := sha256.New()

	secret, err := rsa.EncryptOAEP(seedHash, rand.Reader, pubkey, seed, []byte(""))
	if err != nil {
		t.Errorf("%v", err)
	}

	secretCipher, err := aes.NewCipher(secret[:32])

	if err != nil {
		t.Errorf("%v", err)
	}

	secretCFBEncrypter := cipher.NewCFBEncrypter(secretCipher, []byte("aaaaaaaaaaaaaaaa"))
	secretCFBEncrypter.XORKeyStream(encCred, credential)

	symEncKey, err := legacy.KDFa(legacy.AlgSHA256, seed, "", nil, nil, 256)
	if err != nil {
		t.Errorf("%v", err)
	}

	symEncKeyCipher, err := aes.NewCipher(symEncKey)

	if err != nil {
		t.Errorf("%v", err)
	}

	symEncKeyCFBEncrypter := cipher.NewCFBEncrypter(symEncKeyCipher, []byte("aaaaaaaaaaaaaaaa"))
	symEncKeyCFBEncrypter.XORKeyStream(wrapedSecret, secret)

	fmt.Printf("%v", wrapedSecret)
}
