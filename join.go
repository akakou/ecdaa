package ecdaa

import (
	"crypto/x509"
	"encoding/binary"
	"miracl/core"
	"miracl/core/FP256BN"

	"github.com/google/go-tpm/tpm2"
)

type JoinSeed struct {
	Basename []byte
	S2       []byte
	Y2       *FP256BN.BIG
}

func GenJoinSeed(rng *core.RAND) (*JoinSeed, *FP256BN.ECP, error) {
	var seed JoinSeed
	basename := randomBytes(rng, 32)

	hash := newHash()
	hash.writeBytes(basename)

	B, i, err := hash.hashToECP()

	if err != nil {
		return nil, nil, err
	}

	numBuf := make([]byte, binary.MaxVarintLen32)
	binary.PutVarint(numBuf, int64(i))

	s2Buf := append(numBuf, basename[:]...)

	seed.Basename = basename[:]
	seed.S2 = s2Buf
	seed.Y2 = B.GetY()

	return &seed, B, nil
}

type JoinRequest struct {
	Proof *SchnorrProof
	Q     *FP256BN.ECP
}

type JoinRequestTPM struct {
	JoinReq *JoinRequest
	Public  *tpm2.TPM2BPublic
	EKCert  *x509.Certificate
	SrkName []byte
}

/**
 * Step2. generate request for join (by Member)
 */
func GenJoinReq(seed *JoinSeed, rng *core.RAND) (*JoinRequest, *FP256BN.BIG, error) {
	/* create key and get public key */
	sk := randomBig(rng)

	/* set zero buffers to P1 */
	hash := newHash()
	hash.writeBytes(seed.S2)
	bX := hash.sumToBIG()

	B := FP256BN.NewECPbigs(bX, seed.Y2)
	// get result (Q)
	Q := B.Mul(sk)

	proof := proveSchnorr([]byte(""), seed.Basename, sk, B, B, rng)

	req := JoinRequest{
		proof,
		Q,
	}

	return &req, sk, nil
}

func VerifyJoinReq(req *JoinRequest, seed *JoinSeed, B *FP256BN.ECP) error {
	return verifySchnorr([]byte(""), seed.Basename, req.Proof, B, req.Q)
}

type JoinSeeds struct {
	Basename []byte
	S2       []byte
	Y2       *FP256BN.BIG
}

// type JoinRequest struct {
// 	Public  *tpm2.TPM2BPublic
// 	EKCert  *x509.Certificate
// 	C1      *FP256BN.BIG
// 	S1      *FP256BN.BIG
// 	N       *FP256BN.BIG
// 	Q       *FP256BN.ECP
// 	SrkName []byte
// }

// type CredCipher struct {
// 	WrappedCredential []byte
// 	IdObject          []byte
// 	EncA              []byte
// 	EncC              []byte
// 	IV                []byte
// }

// type IssuerJoinSession struct {
// 	Cred *Credential
// }

// type MemberSession struct {
// 	B *FP256BN.ECP
// 	D *FP256BN.ECP

// 	SrkHandle *tpm2.NamedHandle
// 	EkHandle  *tpm2.AuthHandle
// }

// /**
//  * Step1. generate seed for join (by Issuer)
//  */
// func (_ *Issuer) GenSeedForJoin(rng *core.RAND) (*JoinSeeds, *IssuerJoinSession, error) {
// 	var seed JoinSeeds
// 	var session IssuerJoinSession

// 	basename := randomBytes(rng, 32)

// 	hash := newHash()
// 	hash.writeBytes(basename)

// 	B, i, err := hash.hashToECP()

// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	numBuf := make([]byte, binary.MaxVarintLen32)
// 	binary.PutVarint(numBuf, int64(i))

// 	s2Buf := append(numBuf, basename[:]...)

// 	seed.Basename = basename[:]
// 	seed.S2 = s2Buf
// 	seed.Y2 = B.GetY()

// 	session.Cred = &Credential{
// 		B: B,
// 	}

// 	return &seed, &session, nil
// }

// /**
//  * Step2. generate request for join (by Member)
//  */
// func (member *Member) GenReqForJoinWithTPM(seeds *JoinSeeds, rng *core.RAND) (*JoinRequest, *MemberSession, error) {
// 	var req JoinRequest
// 	var session MemberSession

// 	/* create key and get public key */
// 	handle, ekHandle, srkHandle, _, err := (*member.Tpm).CreateKey()

// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	/* set zero buffers to P1 */
// 	hash := newHash()
// 	hash.writeBytes(seeds.S2)
// 	bX := hash.sumToBIG()

// 	B := FP256BN.NewECPbigs(bX, seeds.Y2)

// 	xBuf := bigToBytes(B.GetX())
// 	yBuf := bigToBytes(B.GetY())

// 	P1 := tpm2.TPMSECCPoint{
// 		X: tpm2.TPM2BECCParameter{
// 			Buffer: xBuf,
// 		},
// 		Y: tpm2.TPM2BECCParameter{
// 			Buffer: yBuf,
// 		},
// 	}

// 	/* set up argument for commit */
// 	S2 := tpm2.TPM2BSensitiveData{
// 		Buffer: seeds.S2[:],
// 	}

// 	Y2 := tpm2.TPM2BECCParameter{
// 		Buffer: yBuf,
// 	}

// 	/* run commit and get U1 */
// 	comRsp, err := (*member.Tpm).Commit(handle, &P1, &S2, &Y2)

// 	if err != nil {
// 		return nil, nil, fmt.Errorf("commit error: %v", err)
// 	}

// 	// get result (Q)
// 	K := parseECPFromTPMFmt(&comRsp.K.Point)
// 	Q := K

// 	// get result (U1)
// 	E := parseECPFromTPMFmt(&comRsp.E.Point)
// 	U1 := E

// 	/* calc hash c2 = H( U1 | P1 | Q | m ) */
// 	hash = newHash()

// 	hash.writeECP(U1, B, Q)

// 	c2 := hash.sumToBIG()

// 	/* sign and get s1, n */
// 	c2Buf := bigToBytes(c2)

// 	sign, err := (*member.Tpm).Sign(c2Buf[:], comRsp.Counter, handle)

// 	if err != nil {
// 		return nil, nil, fmt.Errorf("sign error: %v", err)
// 	}

// 	s1 := FP256BN.FromBytes(sign.Signature.Signature.ECDAA.SignatureS.Buffer)
// 	n := FP256BN.FromBytes(sign.Signature.Signature.ECDAA.SignatureR.Buffer)

// 	/* calc hash c1 = H( n | c2 ) */
// 	hash = newHash()
// 	hash.writeBIG(n)
// 	hash.writeBytes(c2Buf[:])
// 	c1 := hash.sumToBIG()

// 	req.S1 = s1
// 	req.C1 = c1
// 	req.N = n

// 	// todo: remove
// 	req.Q = Q
// 	req.EKCert, err = (*member.Tpm).ReadEKCert()

// 	if err != nil {
// 		return nil, nil, fmt.Errorf("sign error: %v", err)
// 	}

// 	session.B = B
// 	session.D = Q

// 	session.EkHandle = ekHandle
// 	session.SrkHandle = srkHandle

// 	keyHandles := KeyHandles{
// 		EkHandle:  ekHandle,
// 		SrkHandle: srkHandle,
// 		Handle:    handle,
// 	}

// 	member.KeyHandles = &keyHandles

// 	// todo: remove
// 	req.SrkName = srkHandle.Name.Buffer

// 	return &req, &session, nil
// }
