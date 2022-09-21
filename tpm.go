package main

import (
	"crypto/x509"

	"github.com/google/go-tpm/tpm2"
)

type TPM interface {
	CreateKey() (*tpm2.AuthHandle, *tpm2.AuthHandle, *tpm2.TPM2BPublic, error)
	Commit(handle *tpm2.AuthHandle, P1 *tpm2.TPMSECCPoint, S2 *tpm2.TPM2BSensitiveData, Y2 *tpm2.TPM2BECCParameter) (*tpm2.CommitResponse, error)
	Sign(digest []byte, count uint16, handle *tpm2.AuthHandle) (*tpm2.SignResponse, error)
	ReadEKCert() (*x509.Certificate, error)
	Close()
}
