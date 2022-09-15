package main

import (
	"miracl/core"
	"miracl/core/FP256BN"

	"crypto/x509"

	"github.com/google/go-tpm/tpm2"
)

type SWTPM struct {
	sk  *FP256BN.BIG
	r1  *FP256BN.BIG
	rng *core.RAND
}

func NewSWTPM(rng *core.RAND) *SWTPM {
	tpm := SWTPM{}
	tpm.rng = rng

	return &tpm
}

func (tpm *SWTPM) Close() {
}

func (tpm *SWTPM) CreateKey() (*tpm2.AuthHandle, *tpm2.TPM2BPublic, error) {
	tpm.sk = FP256BN.Random(tpm.rng)
	tpm.sk.Mod(p())

	return nil, nil, nil
}

func (tpm *SWTPM) ReadEKCert() (*x509.Certificate, error) {
	return nil, nil
}

func (tpm *SWTPM) Commit(handle *tpm2.AuthHandle, P1Tpm *tpm2.TPMSECCPoint, S2Tpm *tpm2.TPM2BSensitiveData, Y2Tpm *tpm2.TPM2BECCParameter) (*tpm2.CommitResponse, error) {
	var kXBuf [int(FP256BN.MODBYTES)]byte
	var kYBuf [int(FP256BN.MODBYTES)]byte

	var lXBuf [int(FP256BN.MODBYTES)]byte
	var lYBuf [int(FP256BN.MODBYTES)]byte

	var eXBuf [int(FP256BN.MODBYTES)]byte
	var eYBuf [int(FP256BN.MODBYTES)]byte

	tpm.r1 = FP256BN.Random(tpm.rng)
	tpm.r1.Mod(p())

	P1 := ParseECPFromTPMFmt(P1Tpm)

	// s2 := FP256BN.FromBytes(S2Tpm.Buffer)
	y2 := FP256BN.FromBytes(Y2Tpm.Buffer)

	hash := NewHash()
	hash.WriteBytes(S2Tpm.Buffer)
	h := hash.SumToBIG()

	B := FP256BN.NewECPbigs(h, y2)

	K := B.Mul(tpm.sk)
	L := B.Mul(tpm.r1)
	E := P1.Mul(tpm.r1)

	K.Affine()
	L.Affine()
	E.Affine()

	K.GetX().ToBytes(kXBuf[:])
	K.GetY().ToBytes(kYBuf[:])

	L.GetX().ToBytes(lXBuf[:])
	L.GetY().ToBytes(lYBuf[:])

	E.GetX().ToBytes(eXBuf[:])
	E.GetY().ToBytes(eYBuf[:])

	rspC := tpm2.CommitResponse{
		K: tpm2.TPM2BECCPoint{
			Point: tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: kXBuf[:],
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: kYBuf[:],
				},
			},
		},
		L: tpm2.TPM2BECCPoint{
			Point: tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: lXBuf[:],
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: lYBuf[:],
				},
			},
		},
		E: tpm2.TPM2BECCPoint{
			Point: tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: eXBuf[:],
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: eYBuf[:],
				},
			},
		},
	}

	return &rspC, nil
}

func (tpm *SWTPM) Sign(digest []byte, count uint16, handle *tpm2.AuthHandle) (*tpm2.SignResponse, error) {
	var nBuf [int(FP256BN.MODBYTES)]byte
	var s1Buf [int(FP256BN.MODBYTES)]byte

	n := FP256BN.Random(tpm.rng)
	n.Mod(p())

	hash := NewHash()
	hash.WriteBIG(n)
	hash.WriteBytes(digest)
	c1 := hash.SumToBIG()

	s1 := FP256BN.Modmul(c1, tpm.sk, p())
	s1 = FP256BN.Modadd(tpm.r1, s1, p())

	s1.ToBytes(s1Buf[:])
	n.ToBytes(nBuf[:])

	rspS := tpm2.SignResponse{
		Signature: tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgECDAA,
			Signature: tpm2.TPMUSignature{
				ECDAA: &tpm2.TPMSSignatureECC{
					SignatureR: tpm2.TPM2BECCParameter{
						Buffer: nBuf[:],
					},
					SignatureS: tpm2.TPM2BECCParameter{
						Buffer: s1Buf[:],
					},
				},
			},
		},
	}

	return &rspS, nil
}
