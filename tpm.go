package main

import (
	"crypto/x509"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

var password = []byte("hello")

type PublicParams struct {
	primary tpm2.TPMTPublic
	key     tpm2.TPMTPublic
}

func publicParams() PublicParams {
	var params PublicParams

	primary := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Decrypt:             true,
			Restricted:          true,
		},
		Parameters: tpm2.TPMUPublicParms{
			ECCDetail: &tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.TPMUSymKeyBits{
						AES: tpm2.NewKeyBits(128),
					},
					Mode: tpm2.TPMUSymMode{
						AES: tpm2.NewAlgID(tpm2.TPMAlgCFB),
					},
				},
				CurveID: tpm2.TPMECCNistP256,
				KDF: tpm2.TPMTKDFScheme{
					Scheme: tpm2.TPMAlgNull,
				},
			},
		},
	}

	key := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			UserWithAuth:        true,
			SensitiveDataOrigin: true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.TPMUPublicParms{
			ECCDetail: &tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgNull,
				},
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDAA,
					Details: tpm2.TPMUAsymScheme{
						ECDAA: &tpm2.TPMSSigSchemeECDAA{
							HashAlg: tpm2.TPMAlgSHA256,
							Count:   0,
						},
					},
				},
				CurveID: tpm2.TPMECCBNP256,
				KDF: tpm2.TPMTKDFScheme{
					Scheme: tpm2.TPMAlgNull,
				},
			},
		},
	}

	params.primary = primary
	params.key = key

	return params
}

func CreateKey() (*tpm2.AuthHandle, *tpm2.TPM2BPublic, *tpm2.TPM2BPublic, error) {
	thetpm, err := transport.OpenTPM("/dev/tpm0")
	if err != nil {
		return nil, nil, nil, err
	}

	defer thetpm.Close()

	params := publicParams()
	auth := tpm2.PasswordAuth(password)

	primary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: password,
				},
			},
		},
		InPublic: tpm2.TPM2BPublic{
			PublicArea: params.primary,
		},
	}

	rspCP, err := primary.Execute(thetpm)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create primary: %v", err)
	}

	create := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: rspCP.ObjectHandle,
			Name:   rspCP.Name,
			Auth:   auth,
		},

		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: password,
				},
			},
		},

		InPublic: tpm2.TPM2BPublic{
			PublicArea: params.key,
		},
	}

	rspC, err := create.Execute(thetpm)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create: %v", err)
	}

	load := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: rspCP.ObjectHandle,
			Name:   rspCP.Name,
			Auth:   auth,
		},
		InPrivate: rspC.OutPrivate,
		InPublic:  rspC.OutPublic,
	}

	rspL, err := load.Execute(thetpm)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load: %v", err)
	}

	handle := tpm2.AuthHandle{
		Handle: rspL.ObjectHandle,
		Name:   rspL.Name,
		Auth:   auth,
	}

	return &handle, &rspCP.OutPublic, &rspC.OutPublic, nil
}

func ReadEKCert() (*x509.Certificate, error) {
	// TODO: rspRP.NVPublic.NVPublic.DataSize may be wrong or required to process.
	// Because we don't know how to fix it now, we remove data based on fixed value.  
	removeLen := 825 

	certIndex := 0x1C0000A
	nvIndex := tpm2.TPMHandle(certIndex)

	result := []byte{}

	thetpm, err := transport.OpenTPM("/dev/tpm0")
	if err != nil {
		return nil, err
	}
	defer thetpm.Close()

	readPub := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}

	rspRP, err := readPub.Execute(thetpm)

	if err != nil {
		return nil, fmt.Errorf("read public: %w", err)
	}

	for i := 0; i < int(rspRP.NVPublic.NVPublic.DataSize)-removeLen; i++ {
		read := tpm2.NVRead{
			AuthHandle: tpm2.NamedHandle{
				Handle: rspRP.NVPublic.NVPublic.NVIndex,
				Name:   rspRP.NVName,
			},
			NVIndex: tpm2.NamedHandle{
				Handle: rspRP.NVPublic.NVPublic.NVIndex,
				Name:   rspRP.NVName,
			},
			Size:   1,
			Offset: uint16(i),
		}

		rspNV, err := read.Execute(thetpm)

		if err != nil {
			return nil, fmt.Errorf("read: %w", err)
		}

		result = append(result, rspNV.Data.Buffer...)

	}

	cert, err := x509.ParseCertificate(result)

	if err != nil {
		return nil, fmt.Errorf("parsing EK cert: %v", err)
	}

	return cert, nil

}

func Commit(handle *tpm2.AuthHandle, P1 *tpm2.TPMSECCPoint, S2 *tpm2.TPM2BSensitiveData, Y2 *tpm2.TPM2BECCParameter) (*tpm2.CommitResponse, error) {
	thetpm, err := transport.OpenTPM("/dev/tpm0")
	if err != nil {
		return nil, err
	}

	defer thetpm.Close()

	commit := tpm2.Commit{
		SignHandle: tpm2.AuthHandle{
			Handle: handle.Handle,
			Name:   handle.Name,
			Auth:   tpm2.PasswordAuth(password),
		},
		P1: tpm2.TPM2BECCPoint{
			Point: *P1,
		},
		S2: *S2,
		Y2: *Y2,
	}

	rspC, err := commit.Execute(thetpm)
	if err != nil {
		return nil, fmt.Errorf("commit: %v", err)
	}

	return rspC, nil
}

func Sign(digest []byte, count uint16, handle *tpm2.AuthHandle) (*tpm2.SignResponse, error) {
	thetpm, err := transport.OpenTPM("/dev/tpm0")
	if err != nil {
		return nil, err
	}

	sign := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: handle.Handle,
			Name:   handle.Name,
			Auth:   tpm2.PasswordAuth(password),
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: digest[:],
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDAA,
			Details: tpm2.TPMUSigScheme{
				ECDAA: &tpm2.TPMSSchemeECDAA{
					HashAlg: tpm2.TPMAlgSHA256,
					Count:   count,
				},
			},
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	rspS, err := sign.Execute(thetpm)

	if err != nil {
		return nil, fmt.Errorf("sign: %v", err)
	}

	return rspS, nil
}
