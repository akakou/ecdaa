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
func (_ *Member) genReqForJoin(seeds *JoinSeeds, rng *core.RAND) (*JoinRequest, error) {
	msg := []byte("BASENAME")

	var req JoinRequest
	handle, _, public, err := CreateKey()

	if err != nil {
		return nil, err
	}

	Q := ParseECPFromTPMFmt(public.PublicArea.Unique.ECC)

	var xBuf [int(FP256BN.MODBYTES)]byte
	var yBuf [int(FP256BN.MODBYTES)]byte
	var y2Buf [int(FP256BN.MODBYTES)]byte

	g1().GetX().ToBytes(xBuf[:])
	g1().GetY().ToBytes(yBuf[:])

	P1 := tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{
			Buffer: xBuf[:],
		},
		Y: tpm2.TPM2BECCParameter{
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

	S2 := tpm2.TPM2BSensitiveData{
		Buffer: s2Buf[:],
	}

	Y2 := tpm2.TPM2BECCParameter{
		Buffer: y2Buf[:],
	}

	comResp, err := Commit(handle, &P1, &S2, &Y2)

	if err != nil {
		return nil, fmt.Errorf("commmit error: %v\n", err)
	}

	hash = NewHash()

	// U1
	E := ParseECPFromTPMFmt(&comResp.E.Point)
	U1 := E

	// P1
	hash.WriteECP(U1, B)

	// Q
	hash.WriteECP2(g2())

	c2 := hash.SumToBIG()

	fmt.Printf("hash: %v\n", c2)

	var c2bytes [32]byte
	sign, err := Sign(c2bytes[:], comResp.Counter, handle)

	if err != nil {
		return nil, fmt.Errorf("sign error: %v\n", err)
	}

	s1 := FP256BN.FromBytes(sign.Signature.Signature.ECDAA.SignatureS.Buffer)
	// n := FP256BN.FromBytes(sign.Signature.Signature.ECDAA.SignatureR.Buffer)

	fmt.Printf("%v\n", sign.Signature)

	hash = NewHash()

	hash.WriteBIG(c2)
	hash.WriteBytes(sign.Signature.Signature.ECDAA.SignatureR.Buffer)

	c1 := hash.SumToBIG()

	UDashTmp1 := FP256BN.NewECP()
	UDashTmp1.Copy(B)
	UDashTmp1.Mul(s1)

	UDashTmp2 := FP256BN.NewECP()
	UDashTmp2.Copy(Q)

	minC1 := zero().Minus(c1)
	UDashTmp2.Mul(minC1)

	UDashTmp1.Add(UDashTmp2)

	if !compECP(*U1, *UDashTmp1) {
		return nil, fmt.Errorf("not match (`%v` != `%v`)", *U1, *UDashTmp1)
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
