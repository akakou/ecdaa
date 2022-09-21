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
	tpm, err := OpenRealTPM()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	_, ekHandle, _, _ := tpm.CreateKey()

	srkCreate := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic: tpm2.TPM2BPublic{
			PublicArea: tpm2.ECCSRKTemplate,
		},
	}

	srkCreateRsp, err := srkCreate.Execute(tpm.tpm)
	if err != nil {
		t.Fatalf("could not generate SRK: %v", err)
	}

	secret := tpm2.TPM2BDigest{Buffer: []byte("Secrets!!!")}

	mc := tpm2.MakeCredential{
		Handle:      ekHandle.Handle,
		Credential:  secret,
		ObjectNamae: srkCreateRsp.Name,
	}

	mcRsp, err := mc.Execute(tpm.tpm)
	if err != nil {
		t.Fatalf("could not make credential: %v", err)
	}

	ac := tpm2.ActivateCredential{
		ActivateHandle: tpm2.NamedHandle{
			Handle: srkCreateRsp.ObjectHandle,
			Name:   srkCreateRsp.Name,
		},
		KeyHandle:      *ekHandle,
		CredentialBlob: mcRsp.CredentialBlob,
		Secret:         mcRsp.Secret,
	}

	acRsp, err := ac.Execute(tpm.tpm)
	if err != nil {
		t.Fatalf("could not activate credential: %v", err)
	}

	if !bytes.Equal(acRsp.CertInfo.Buffer, secret.Buffer) {
		t.Errorf("want %x got %x", secret.Buffer, acRsp.CertInfo.Buffer)
	}
}
