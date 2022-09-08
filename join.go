package main

import (
	"encoding/binary"
	"fmt"
	"miracl/core"
	"miracl/core/FP256BN"

	"github.com/google/certificate-transparency-go/x509"

	"github.com/google/go-tpm/tpm2"
)

type JoinSeeds struct {
	m *FP256BN.BIG
	B *FP256BN.ECP
}

type JoinRequest struct {
	public *tpm2.TPM2BPublic
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
func (member *Member) genReqForJoin(seeds *JoinSeeds, rng *core.RAND) (*JoinRequest, error) {
	var req JoinRequest
	basename := []byte("")

	/* create key and get public key */
	handle, _, err := (*member.tpm).CreateKey()

	if err != nil {
		return nil, err
	}

	// the public key is named "Q"
	// Q := ParseECPFromTPMFmt(public.PublicArea.Unique.ECC)

	/* calc hash */
	var y2Buf [int(FP256BN.MODBYTES)]byte

	hash := NewHash()
	hash.WriteBytes(basename)

	B, i, err := hash.HashToECP()

	if err != nil {
		return nil, err
	}

	numBuf := make([]byte, binary.MaxVarintLen32)
	binary.PutVarint(numBuf, int64(i))

	s2Buf := append(numBuf, basename...)
	B.GetY().ToBytes(y2Buf[:])

	/* set zero buffers to P1 */
	var xBuf [int(FP256BN.MODBYTES)]byte
	var yBuf [int(FP256BN.MODBYTES)]byte

	B.GetX().ToBytes(xBuf[:])
	B.GetY().ToBytes(yBuf[:])

	P1 := tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{
			Buffer: xBuf[:],
		},
		Y: tpm2.TPM2BECCParameter{
			Buffer: yBuf[:],
		},
	}

	/* set up argument for commit */
	S2 := tpm2.TPM2BSensitiveData{
		Buffer: s2Buf[:],
	}

	Y2 := tpm2.TPM2BECCParameter{
		Buffer: y2Buf[:],
	}

	/* run commit and get U1 */
	comResp, err := (*member.tpm).Commit(handle, &P1, &S2, &Y2)

	if err != nil {
		return nil, fmt.Errorf("commit error: %v\n", err)
	}

	// get result (Q)
	K := ParseECPFromTPMFmt(&comResp.K.Point)
	Q := K

	// get result (U1)
	E := ParseECPFromTPMFmt(&comResp.E.Point)
	U1 := E

	/* calc hash c2 = H( U1 | P1 | Q | m ) */
	hash = NewHash()

	// P1
	hash.WriteECP(U1, B, Q)

	c2 := hash.SumToBIG()

	/* sign and get s1, n */
	var c2Bytes [32]byte
	c2.ToBytes(c2Bytes[:])

	sign, err := (*member.tpm).Sign(c2Bytes[:], comResp.Counter, handle)

	if err != nil {
		return nil, fmt.Errorf("sign error: %v\n", err)
	}

	s1 := FP256BN.FromBytes(sign.Signature.Signature.ECDAA.SignatureS.Buffer)
	n := FP256BN.FromBytes(sign.Signature.Signature.ECDAA.SignatureR.Buffer)

	/* calc hash c1 = H( n | c2 ) */
	hash = NewHash()
	hash.WriteBIG(n, c2)

	c1 := hash.SumToBIG()

	/* compare U1 ?= B^s1 Q^-c1   */
	// UDashTmp1 = B^s1
	UDashTmp := FP256BN.NewECP()
	UDashTmp.Copy(B)
	UDashTmp = UDashTmp.Mul(s1)

	// UDashTmp2 = Q^-c1
	UDashTmp2 := FP256BN.NewECP()
	UDashTmp2.Copy(Q)

	minusC1 := FP256BN.Modneg(c1, p())
	UDashTmp2 = UDashTmp2.Mul(minusC1)

	// UDashTmp1 * UDashTmp2 = B^s1 Q^-c1
	UDashTmp.Add(UDashTmp2)

	if !compECP(U1, UDashTmp) {
		return nil, fmt.Errorf("U is not match (`%v` != `%v`)", U1.ToString(), UDashTmp.ToString())

	}

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
