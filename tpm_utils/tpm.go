package tpm_utils

import (
	"crypto/x509"
	"fmt"
	"mcl_utils"
	"miracl/core/FP256BN"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	// "github.com/google/go-tpm/tpm2/transport/simulator"
)

const TPM_PATH = "/dev/tpm0"

func ekPolicy(t transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
	cmd := tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		PolicySession: handle,
		NonceTPM:      nonceTPM,
	}
	_, err := cmd.Execute(t)
	return err
}

type TPM struct {
	tpm      transport.TPMCloser
	password []byte
}

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
			UserWithAuth:        false,
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
			AdminWithPolicy:     true,
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

func OpenTPM(password []byte, path string) (*TPM, error) {
	// thetpm, err := simulator.OpenSimulator()
	thetpm, err := transport.OpenTPM(path)

	if err != nil {
		return nil, err
	}

	tpm := TPM{
		tpm:      thetpm,
		password: password,
	}

	return &tpm, nil
}

func (tpm *TPM) Close() {
	tpm.tpm.Close()
}

func (tpm *TPM) CreateKey() (*tpm2.AuthHandle, *tpm2.AuthHandle, *tpm2.NamedHandle, *tpm2.TPM2BPublic, error) {
	params := publicParams()
	auth := tpm2.PasswordAuth(tpm.password)

	ekCreate := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic: tpm2.TPM2BPublic{
			PublicArea: tpm2.RSAEKTemplate,
		},
	}

	ekCreateRsp, err := ekCreate.Execute(tpm.tpm)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("create ek: %v", err)
	}

	srkCreate := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic: tpm2.TPM2BPublic{
			PublicArea: tpm2.ECCSRKTemplate,
		},
	}

	srkCreateRsp, err := srkCreate.Execute(tpm.tpm)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("create SRK: %v", err)
	}

	srkHandle := tpm2.NamedHandle{
		Handle: srkCreateRsp.ObjectHandle,
		Name:   srkCreateRsp.Name,
	}

	create := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: tpm.password,
				},
			},
		},
		InPublic: tpm2.TPM2BPublic{
			PublicArea: params.key,
		},
	}

	ekHandle := tpm2.AuthHandle{
		Handle: ekCreateRsp.ObjectHandle,
		Name:   ekCreateRsp.Name,
		Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy),
	}

	rspC, err := create.Execute(tpm.tpm)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("create: %v", err)
	}

	handle := tpm2.AuthHandle{
		Handle: rspC.ObjectHandle,
		Name:   rspC.Name,
		Auth:   auth,
	}

	return &handle, &ekHandle, &srkHandle, &rspC.OutPublic, nil
}

func (tpm *TPM) ActivateCredential(ekHandle *tpm2.AuthHandle, srkHandle *tpm2.NamedHandle, idObject, wrappedCredential []byte) ([]byte, error) {
	var parsedIdObject tpm2.TPM2BIDObject
	var parsedWrappedCredential tpm2.TPM2BEncryptedSecret

	err := tpm2.Unmarshal(idObject, &parsedIdObject)

	if err != nil {
		return nil, fmt.Errorf("unmarshal: %v", err)
	}

	err = tpm2.Unmarshal(wrappedCredential, &parsedWrappedCredential)

	if err != nil {
		return nil, fmt.Errorf("unmarshal: %v", err)
	}

	ac := tpm2.ActivateCredential{
		ActivateHandle: *srkHandle,
		KeyHandle:      *ekHandle,
		CredentialBlob: parsedIdObject,
		Secret:         parsedWrappedCredential,
	}

	acRsp, err := ac.Execute(tpm.tpm)
	if err != nil {
		return nil, fmt.Errorf("activate credential: %v", err)
	}

	return acRsp.CertInfo.Buffer, nil
}

func (tpm *TPM) ReadEKCert() (*x509.Certificate, error) {
	nvIndex := tpm2.TPMHandle(EK_CERT_INDEX)

	result := []byte{}

	readPub := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}

	rspRP, err := readPub.Execute(tpm.tpm)

	if err != nil {
		return nil, fmt.Errorf("read public: %w", err)
	}

	for i := 0; i < int(rspRP.NVPublic.NVPublic.DataSize); i++ {
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

		rspNV, err := read.Execute(tpm.tpm)

		if err != nil {
			return nil, fmt.Errorf("read: %w", err)
		}

		result = append(result, rspNV.Data.Buffer...)
	}

	// TODO: rspRP.NVPublic.NVPublic.DataSize may be wrong or required to process.
	// Because we don't know how to fix it now, we remove data based on fixed value.
	resultSize := 0

	for {
		resultSize = len(result)

		if result[resultSize-1] == 255 && resultSize != 0 {
			result = result[:resultSize-1]
		} else {
			break
		}
	}

	cert, err := x509.ParseCertificate(result)

	if err != nil {
		return nil, fmt.Errorf("parsing EK cert: %v", err)
	}

	return cert, nil
}

func (tpm *TPM) Commit(handle *tpm2.AuthHandle, P1_ECP *FP256BN.ECP, S2_bytes []byte, P2 *FP256BN.ECP) (*tpm2.CommitResponse, *FP256BN.ECP, *FP256BN.ECP, *FP256BN.ECP, error) {
	/* set zero buffers to P1 */
	xBuf := mcl_utils.BigToBytes(P1_ECP.GetX())
	yBuf := mcl_utils.BigToBytes(P1_ECP.GetY())

	P1 := tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{
			Buffer: xBuf,
		},
		Y: tpm2.TPM2BECCParameter{
			Buffer: yBuf,
		},
	}

	/* set up argument for commit */
	S2 := tpm2.TPM2BSensitiveData{
		Buffer: S2_bytes,
	}

	Y2 := tpm2.TPM2BECCParameter{
		Buffer: mcl_utils.BigToBytes(P2.GetY()),
	}

	commit := tpm2.Commit{
		SignHandle: tpm2.AuthHandle{
			Handle: handle.Handle,
			Name:   handle.Name,
			Auth:   tpm2.PasswordAuth(tpm.password),
		},
		P1: tpm2.TPM2BECCPoint{
			Point: P1,
		},
		S2: S2,
		Y2: Y2,
	}

	rspC, err := commit.Execute(tpm.tpm)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("commit: %v", err)
	}

	E := parseECPFromTPMFmt(&rspC.E.Point)
	L := parseECPFromTPMFmt(&rspC.L.Point)
	K := parseECPFromTPMFmt(&rspC.K.Point)

	return rspC, E, L, K, nil
}

func (tpm *TPM) Sign(digest []byte, count uint16, handle *tpm2.AuthHandle) (*tpm2.SignResponse, *FP256BN.BIG, *FP256BN.BIG, error) {
	sign := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: handle.Handle,
			Name:   handle.Name,
			Auth:   tpm2.PasswordAuth(tpm.password),
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

	rspS, err := sign.Execute(tpm.tpm)

	if err != nil {
		return nil, nil, nil, fmt.Errorf("sign: %v", err)
	}

	s1 := FP256BN.FromBytes(rspS.Signature.Signature.ECDAA.SignatureS.Buffer)
	n := FP256BN.FromBytes(rspS.Signature.Signature.ECDAA.SignatureR.Buffer)

	return rspS, s1, n, nil
}
