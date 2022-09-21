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
	"github.com/google/go-tpm/tpm2"
)

func TestCreateKey(t *testing.T) {
	tpm, err := OpenRealTPM()
	defer tpm.Close()

	if err != nil {
		t.Errorf("%v", err)
	}

	handle, _, keyP, err := tpm.CreateKey()

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
	// credential := []byte("hello")
	// encCred := make([]byte, len(credential))
	wrapedSecret := make([]byte, int(32))

	tpm, err := OpenRealTPM()
	defer tpm.Close()

	if err != nil {
		t.Errorf("%v", err)
	}

	iv := []byte("0123456789abcdef")

	_, ekHandle, _, err := tpm.CreateKey()

	if err != nil {
		t.Errorf("%v", err)
	}

	cert, err := tpm.ReadEKCert()

	if err != nil {
		t.Errorf("%v", err)
	}

	pubkey := cert.PublicKey.(*rsa.PublicKey)

	// 1. seed ←? Zp
	seed := []byte("seed")

	// 2. secret = F?(seed)
	secret, err := legacy.KDFa(legacy.AlgSHA256, seed, "", nil, nil, 32*8)
	if err != nil {
		t.Errorf("%v", err)
	}

	// 3. encrypted_credential = enc(credential, secret)
	// secretCipher, err := aes.NewCipher(secret)

	// if err != nil {
	// 	t.Errorf("%v", err)
	// }

	// secretCFBEncrypter := cipher.NewCFBEncrypter(secretCipher, iv)
	// secretCFBEncrypter.XORKeyStream(encCred, credential)

	// 5. hmac, symmetric_encryption_key = KDFa(seed, name)
	symEncKey, err := legacy.KDFa(legacy.AlgSHA256, seed, "", nil, nil, 32*8)
	if err != nil {
		t.Errorf("%v", err)
	}

	symEncKeyCipher, err := aes.NewCipher(symEncKey)

	if err != nil {
		t.Errorf("%v", err)
	}

	symEncKeyCFBEncrypter := cipher.NewCFBEncrypter(symEncKeyCipher, iv)
	symEncKeyCFBEncrypter.XORKeyStream(wrapedSecret, secret)

	// 6. encrypted_seed = enc(seed, EK-C)
	encSeed, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubkey, seed, []byte("IDENTITY"))
	if err != nil {
		t.Errorf("%v", err)
	}

	// read srkCreate key
	srkCreate := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic: tpm2.TPM2BPublic{
			PublicArea: tpm2.RSASRKTemplate,
		},
	}

	srkCreateRsp, err := srkCreate.Execute(tpm.tpm)
	if err != nil {
		t.Fatalf("could not generate SRK: %v", err)
	}

	// 5. activate credential
	ac := tpm2.ActivateCredential{
		ActivateHandle: tpm2.NamedHandle{
			Handle: srkCreateRsp.ObjectHandle,
			Name:   srkCreateRsp.Name,
		},
		KeyHandle: *ekHandle,
		CredentialBlob: tpm2.TPM2BIDObject{
			Buffer: wrapedSecret,
		},
		Secret: tpm2.TPM2BEncryptedSecret{
			Buffer: encSeed,
		},
	}

	acRsp, err := ac.Execute(tpm.tpm)
	if err != nil {
		t.Fatalf("could not activate credential: %v", err)
	}

	fmt.Printf("cert: %v\n", acRsp.CertInfo.Buffer)
}
