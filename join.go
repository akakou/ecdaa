package main

import (
	"encoding/binary"
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
func (_ *Issuer) genSeedForJoin(rng *core.RAND) (*JoinSeeds, error) {
	var seed JoinSeeds

	// m := FP256BN.Random(rng)
	// m := g1().GetX()
	// B, i, err := HashToECP([]byte{0x01})

	// if err != nil {
	// 	return nil, fmt.Errorf("%v\n", err)
	// }

	// seed.m = m
	// seed.B = B

	return &seed, nil
}

/**
 * Step2. generate request for join (by Member)
 */
func (_ *Member) genReqForJoin(seeds *JoinSeeds, rng *core.RAND) (*JoinRequest, error) {
	msg := []byte("BASENAME")

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
	var y2Buf [int(FP256BN.MODBYTES)]byte

	g1().GetX().ToBytes(xBuf[:])
	g1().GetY().ToBytes(yBuf[:])

	P1 := tpms.ECCPoint{
		X: tpm2b.ECCParameter{
			Buffer: xBuf[:],
		},
		Y: tpm2b.ECCParameter{
			Buffer: yBuf[:],
		},
	}

	hash := NewHash()
	hash.WriteBytes(msg)

	B, i, err := hash.HashToECP()

	if err != nil {
		return nil, err
	}

	numBuf := make([]byte, binary.MaxVarintLen32)
	binary.PutVarint(numBuf, int64(i))

	s2Buf := append(numBuf, msg...)
	B.GetY().ToBytes(y2Buf[:])

	S2 := tpm2b.SensitiveData{
		Buffer: s2Buf[:],
	}

	Y2 := tpm2b.ECCParameter{
		Buffer: y2Buf[:],
	}

	comResp, err := Commit(handle, &P1, &S2, &Y2)

	if err != nil {
		return nil, err
	}

	var buffer []byte
	buffer = append(buffer, comResp.K.Point.X.Buffer...)
	buffer = append(buffer, comResp.K.Point.Y.Buffer...)

	buffer = append(buffer, comResp.E.Point.X.Buffer...)
	buffer = append(buffer, comResp.E.Point.Y.Buffer...)

	buffer = append(buffer, msg...)

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
