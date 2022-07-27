package main

import (
	"crypto/x509"

	"github.com/google/go-tpm/direct/helpers"
	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpm2b"
	"github.com/google/go-tpm/direct/structures/tpma"
	"github.com/google/go-tpm/direct/structures/tpms"
	"github.com/google/go-tpm/direct/structures/tpmt"
	"github.com/google/go-tpm/direct/structures/tpmu"
	"github.com/google/go-tpm/direct/tpm2"
	"github.com/google/go-tpm/direct/transport"
)

type PublicParams struct {
	primary tpmt.Public
	key     tpmt.Public
}

func publicParams() PublicParams {
	var params PublicParams

	primary := tpmt.Public{
		Type:    tpm.AlgECC,
		NameAlg: tpm.AlgSHA1,
		ObjectAttributes: tpma.Object{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Decrypt:             true,
			Restricted:          true,
		},
		Parameters: tpmu.PublicParms{
			ECCDetail: &tpms.ECCParms{
				Symmetric: tpmt.SymDefObject{
					Algorithm: tpm.AlgAES,
					KeyBits: tpmu.SymKeyBits{
						AES: helpers.NewKeyBits(128),
					},
					Mode: tpmu.SymMode{
						AES: helpers.NewAlgID(tpm.AlgCFB),
					},
				},
				CurveID: tpm.ECCNistP256,
				KDF: tpmt.KDFScheme{
					Scheme: tpm.AlgNull,
				},
			},
		},
	}

	key := tpmt.Public{
		Type:    tpm.AlgECC,
		NameAlg: tpm.AlgSHA1,
		ObjectAttributes: tpma.Object{
			FixedTPM:            true,
			FixedParent:         true,
			UserWithAuth:        true,
			SensitiveDataOrigin: true,
			SignEncrypt:         true,
		},
		Parameters: tpmu.PublicParms{
			ECCDetail: &tpms.ECCParms{
				Symmetric: tpmt.SymDefObject{
					Algorithm: tpm.AlgNull,
				},
				Scheme: tpmt.ECCScheme{
					Scheme: tpm.AlgECDAA,
					Details: tpmu.AsymScheme{
						ECDAA: &tpms.SigSchemeECDAA{
							HashAlg: tpm.AlgSHA1,
							Count:   1,
						},
					},
				},
				CurveID: tpm.ECCBNP256,
				KDF: tpmt.KDFScheme{
					Scheme: tpm.AlgNull,
				},
			},
		},
	}

	params.primary = primary
	params.key = key

	return params
}

func CreateKey() (*tpm2.CreateLoadedResponse, error) {
	thetpm, err := transport.OpenTPM("/dev/tpm0")
	if err != nil {
		return nil, err
	}

	defer thetpm.Close()

	params := publicParams()

	password := []byte("hello")

	primary := tpm2.CreateLoaded{
		ParentHandle: tpm.RHEndorsement,
		InSensitive: tpm2b.SensitiveCreate{
			Sensitive: tpms.SensitiveCreate{
				UserAuth: tpm2b.Auth{
					Buffer: password,
				},
			},
		},
		InPublic: tpm2b.Template{
			Template: params.primary,
		},
	}

	rspCP, err := primary.Execute(thetpm)
	if err != nil {
		return nil, err
	}

	create := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: rspCP.ObjectHandle,
			Name:   rspCP.Name,
			Auth:   tpm2.PasswordAuth(password),
		},

		InSensitive: tpm2b.SensitiveCreate{
			Sensitive: tpms.SensitiveCreate{
				UserAuth: tpm2b.Auth{
					Buffer: password,
				},
			},
		},
		InPublic: tpm2b.Template{},
	}

	rspC, err := create.Execute(thetpm)
	if err != nil {
		return nil, err
	}

	return rspC, nil
}

func ReadEKCert() (*x509.Certificate, error) {
	// config := &attest.OpenConfig{}

	// tpm, err := attest.OpenTPM(config)
	// if err != nil {
	// 	return nil, err
	// }

	// eks, err := tpm.EKs()
	// if err != nil {
	// 	return nil, err
	// }

	// ek := eks[0]

	// return ek.Certificate, err
	return nil, nil
}
