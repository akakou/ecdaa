package main

import (
	"bytes"
	"crypto/x509"
	"go-tpm/tpm2"

	"github.com/google/go-tpm-tools/client"
)

type PublicParams struct {
	ecdsa tpm2.Public
	ecdaa tpm2.Public
}

func publicParams() PublicParams {
	var params PublicParams

	ecdsa := tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagDecrypt | tpm2.FlagRestricted,
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{Alg: tpm2.AlgAES, KeyBits: 128, Mode: tpm2.AlgCFB},
			Sign: &tpm2.SigScheme{
				Alg: tpm2.AlgNull,
			},
			CurveID: tpm2.CurveNISTP256,
			KDF: &tpm2.KDFScheme{
				Alg: tpm2.AlgNull,
			},
			Point: tpm2.ECPoint{},
		},
	}

	ecdaa := tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagSign,
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{
				Alg: tpm2.AlgNull,
			},
			Sign: &tpm2.SigScheme{
				Alg:   tpm2.AlgECDAA,
				Hash:  tpm2.AlgSHA256,
				Count: 1,
			},
			CurveID: tpm2.CurveBNP256,
			KDF: &tpm2.KDFScheme{
				Alg: tpm2.AlgNull,
			},
			Point: tpm2.ECPoint{},
		},
	}

	params.ecdsa = ecdsa
	params.ecdaa = ecdaa

	return params
}

func CreateKey() (*tpm2.Public, error) {
	pubParam := publicParams()
	pcrSelection7 := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7}}

	emptyPassword := ""

	rw, err := tpm2.OpenTPM()
	if err != nil {
		return nil, err
	}
	defer rw.Close()

	parentHandle, _, err := tpm2.CreatePrimary(rw, tpm2.HandleOwner, pcrSelection7, emptyPassword, emptyPassword, pubParam.ecdsa)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(rw, parentHandle)

	privateBlob, publicBlob, _, _, _, err := tpm2.CreateKey(rw, parentHandle, pcrSelection7, emptyPassword, emptyPassword, pubParam.ecdaa)
	if err != nil {
		return nil, err
	}

	keyHandle, nameData, err := tpm2.Load(rw, parentHandle, emptyPassword, publicBlob, privateBlob)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(rw, keyHandle)

	if _, err := tpm2.DecodeName(bytes.NewBuffer(nameData)); err != nil {
		return nil, err
	}

	pub, _, _, err := tpm2.ReadPublic(rw, keyHandle)
	if err != nil {
		return nil, err
	}

	return &pub, nil
}

func ReadEKCert() (*x509.Certificate, error) {
	rw, err := tpm2.OpenTPM()
	if err != nil {
		return nil, err
	}
	defer rw.Close()

	ek, err := client.EndorsementKeyECC(rw)
	cert := ek.Cert()

	return cert, nil
}
