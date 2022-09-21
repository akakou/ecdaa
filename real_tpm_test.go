package main

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestCreateKey(t *testing.T) {
	tpm, err := OpenRealTPM()
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
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	_, ekHandle, srkHandle, _, _ := tpm.CreateKey()

	secret := tpm2.TPM2BDigest{Buffer: []byte("Secrets!!!")}

	mc := tpm2.MakeCredential{
		Handle:      ekHandle.Handle,
		Credential:  secret,
		ObjectNamae: srkHandle.Name,
	}

	mcRsp, err := mc.Execute(tpm.tpm)
	if err != nil {
		t.Fatalf("could not make credential: %v", err)
	}

	result, err := tpm.ActivateCredential(ekHandle, srkHandle, mcRsp.CredentialBlob.Buffer, mcRsp.Secret.Buffer)

	if err != nil {
		t.Errorf("%v", err)
	}

	if !bytes.Equal(result, secret.Buffer) {
		t.Errorf("want %x got %x", secret.Buffer, result)
	}
}
