package main

import (
	"miracl/core"
	"miracl/core/FP256BN"

	"github.com/google/certificate-transparency-go/x509"

	"github.com/google/go-tpm/direct/structures/tpm2b"
	"github.com/google/go-tpm/direct/structures/tpms"
	"github.com/google/go-tpm/tpm2"
)

type JoinSeeds struct {
	m *FP256BN.BIG
	B *FP256BN.ECP
}

type JoinRequest struct {
	public *tpm2.Public
	cert   *x509.Certificate
}

/**
 * Step1. generate seed for join (by Issuer)
 */
func (_ *Issuer) genSeedForJoin(rng *core.RAND) *JoinSeeds {
	var seed JoinSeeds

	m := FP256BN.Random(rng)
	B := HashFromBIGToECP(m)

	seed.m = m
	seed.B = B

	return &seed
}

/**
 * Step2. generate request for join (by Member)
 */
func (_ *Member) genReqForJoin(seeds *JoinSeeds, rng *core.RAND) (*JoinRequest, error) {
	var req JoinRequest
	handle, _, err := CreateKey()

	if err != nil {
		return nil, err
	}

	cert, err := ReadEKCert()

	if err != nil {
		return nil, err
	}

	var xBuf [int(FP256BN.MODBYTES)]byte
	var yBuf [int(FP256BN.MODBYTES)]byte

	seeds.B.GetX().ToBytes(xBuf[:])
	seeds.B.GetY().ToBytes(yBuf[:])

	P1 := tpms.ECCPoint{
		X: tpm2b.ECCParameter{
			Buffer: xBuf[:],
		},
		Y: tpm2b.ECCParameter{
			Buffer: yBuf[:],
		},
	}

	S2 := tpm2b.SensitiveData{
		Buffer: P1.X.Buffer,
	}

	Y2 := &P1.Y

	_, err = Commit(handle, &P1, &S2, Y2)

	if err != nil {
		return nil, err
	}

	req.cert = cert

	return &req, nil
}

// /**
//  * Step3. make credential for join (by Issuer)
//  */
// func (_ *Member) make_cred(n FP256BN.BIG, rng *core.RAND) JoinRequest {
// 	var req JoinRequest

// 	return req
// }

// /**
//  * Step4. activate credential for join with TPM2_activate_credential (by Member)
//  */
// func (_ *Member) activate_cred(n FP256BN.BIG, rng *core.RAND) JoinRequest {
// 	var req JoinRequest

// 	return req
// }
