package tpm_utils

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"testing"

	legacy "github.com/google/go-tpm/legacy/tpm2"
)


func TestCreateKey(t *testing.T) {
	password := []byte("piyo")

	tpm, err := OpenTPM(password, TPM_PATH)
	defer tpm.Close()

	if err != nil {
		t.Errorf("%v", err)
	}

	handle, _, _, keyP, err := tpm.CreateKey()

	if err != nil {
		t.Errorf("%v", err)
	}

	fmt.Printf("handle: %v\n", handle)
	fmt.Printf("key public key: %v\n", keyP)
}

func TestReadEKCert(t *testing.T) {
	password := []byte("hoge")

	tpm, err := OpenTPM(password, TPM_PATH)
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
	password := []byte("hoge")
	secret := []byte("0123456789abcdef")

	tpm, err := OpenTPM(password, TPM_PATH)
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	_, ekHandle, srkHandle, _, _ := tpm.CreateKey()

	aikName := legacy.HashValue{
		Alg:   legacy.AlgSHA256,
		Value: srkHandle.Name.Buffer,
	}

	cert, err := tpm.ReadEKCert()

	if err != nil {
		t.Fatalf("enc cred: %v", err)
	}

	idObject, wrappedCredential, err := MakeCred(&aikName, cert.PublicKey, 16, secret)

	if err != nil {
		t.Fatalf("enc cred: %v", err)
	}

	result, err := tpm.ActivateCredential(ekHandle, srkHandle, idObject, wrappedCredential)

	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(result, secret) {
		t.Fatalf("want %x got %x", secret, result)
	}
}
