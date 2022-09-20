package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"miracl/core"
	"miracl/core/FP256BN"

	"github.com/google/go-tpm/tpm2"
)

type JoinSeeds struct {
	basename []byte
	s2       []byte
	y2       *FP256BN.BIG
}

type JoinRequest struct {
	public *tpm2.TPM2BPublic
	cert   *x509.Certificate
	c1     *FP256BN.BIG
	s1     *FP256BN.BIG
	n      *FP256BN.BIG
	Q      *FP256BN.ECP
}

type IssuerJoinSession struct {
	B *FP256BN.ECP
}

/**
 * Step1. generate seed for join (by Issuer)
 */
func (_ *Issuer) genSeedForJoin(rng *core.RAND) (*JoinSeeds, *IssuerJoinSession, error) {
	var seed JoinSeeds
	var session IssuerJoinSession
	var basenameBuf [int(FP256BN.MODBYTES)]byte

	basename := FP256BN.Random(rng)
	basename.ToBytes(basenameBuf[:])

	hash := NewHash()
	hash.WriteBytes(basenameBuf[:])

	B, i, err := hash.HashToECP()

	if err != nil {
		return nil, nil, err
	}

	numBuf := make([]byte, binary.MaxVarintLen32)
	binary.PutVarint(numBuf, int64(i))

	s2Buf := append(numBuf, basenameBuf[:]...)

	seed.basename = basenameBuf[:]
	seed.s2 = s2Buf
	seed.y2 = B.GetY()

	session.B = B

	return &seed, &session, nil
}

/**
 * Step2. generate request for join (by Member)
 */
func (member *Member) genReqForJoin(seeds *JoinSeeds, rng *core.RAND) (*JoinRequest, error) {
	var req JoinRequest
	/* create key and get public key */
	handle, _, err := (*member.tpm).CreateKey()

	if err != nil {
		return nil, err
	}

	var xBuf [int(FP256BN.MODBYTES)]byte
	var yBuf [int(FP256BN.MODBYTES)]byte

	/* set zero buffers to P1 */
	hash := NewHash()
	hash.WriteBytes(seeds.s2)
	bX := hash.SumToBIG()

	B := FP256BN.NewECPbigs(bX, seeds.y2)

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
		Buffer: seeds.s2[:],
	}

	Y2 := tpm2.TPM2BECCParameter{
		Buffer: yBuf[:],
	}

	/* run commit and get U1 */
	comRsp, err := (*member.tpm).Commit(handle, &P1, &S2, &Y2)

	if err != nil {
		return nil, fmt.Errorf("commit error: %v\n", err)
	}

	// get result (Q)
	K := ParseECPFromTPMFmt(&comRsp.K.Point)
	Q := K

	// get result (U1)
	E := ParseECPFromTPMFmt(&comRsp.E.Point)
	U1 := E

	/* calc hash c2 = H( U1 | P1 | Q | m ) */
	hash = NewHash()

	hash.WriteECP(U1, B, Q)

	c2 := hash.SumToBIG()

	/* sign and get s1, n */
	var c2Bytes [32]byte
	c2.ToBytes(c2Bytes[:])

	sign, err := (*member.tpm).Sign(c2Bytes[:], comRsp.Counter, handle)

	if err != nil {
		return nil, fmt.Errorf("sign error: %v\n", err)
	}

	s1 := FP256BN.FromBytes(sign.Signature.Signature.ECDAA.SignatureS.Buffer)
	n := FP256BN.FromBytes(sign.Signature.Signature.ECDAA.SignatureR.Buffer)

	/* calc hash c1 = H( n | c2 ) */
	hash = NewHash()
	hash.WriteBIG(n)
	hash.WriteBytes(c2Bytes[:])
	c1 := hash.SumToBIG()

	req.s1 = s1
	req.c1 = c1
	req.n = n

	// todo: remove
	req.Q = Q

	req.cert, err = (*member.tpm).ReadEKCert()

	return &req, nil
}

/**
 * Step3. make credential for join (by Issuer)
 */
func (issuer *Issuer) MakeCred(req *JoinRequest, session *IssuerJoinSession, rng *core.RAND) (*JoinRequest, error) {
	B := session.B
	Q := req.Q

	U1 := B.Mul(req.s1)
	UTmp := Q.Mul(req.c1)

	U1.Sub(UTmp)
	U1.Affine()

	hash := NewHash()
	hash.WriteECP(U1, B, Q)
	c2 := hash.SumToBIG()

	var c2Buf [FP256BN.MODBYTES]byte
	c2.ToBytes(c2Buf[:])

	hash = NewHash()
	hash.WriteBIG(req.n)
	hash.WriteBytes(c2Buf[:])
	c1 := hash.SumToBIG()

	if FP256BN.Comp(c1, req.c1) != 0 {
		return nil, fmt.Errorf("U is not match (`%v` != `%v`)", c1.ToString(), req.c1.ToString())
	}

	var cred Credential

	invY := issuer.ipk.s_y
	invY.Invmodp(p())
	cred.A = B.Mul(invY)
	cred.B = B

	cred.C = FP256BN.NewECP()
	cred.C.Copy(cred.A)
	cred.C.Add(Q)
	cred.C.Mul(issuer.isk.x)

	cred.D = Q

	a := req.cert.PublicKey.(*rsa.PublicKey)
	fmt.Print("%w", a)

	// ac := tpm2.ActivateCredential{
	// 	ActivateHandle: tpm2.NamedHandle{
	// 		Handle: srkCreateRsp.ObjectHandle,
	// 		Name:   srkCreateRsp.Name,
	// 	},
	// 	KeyHandle: tpm2.AuthHandle{
	// 		Handle: ekCreateRsp.ObjectHandle,
	// 		Name:   ekCreateRsp.Name,
	// 		Auth:   Policy(TPMAlgSHA256, 16, ekPolicy),
	// 	},
	// 	CredentialBlob: mcRsp.CredentialBlob,
	// 	Secret:         mcRsp.Secret,
	// }

	return req, nil
}

// /**
//  * Step4. activate credential for join with TPM2_activate_credential (by Member)
//  */
// func (_ *Member) activate_cred(n FP256BN.BIG, rng *core.RAND) JoinRequest {
// 	var req JoinRequest

// 	return req
// }
