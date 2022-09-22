package main

import (
	"encoding/binary"
	"fmt"
	"miracl/core"
	"miracl/core/FP256BN"

	"github.com/google/go-tpm/tpm2"
)

type Member struct {
	tpm        *TPM
	keyHandles *KeyHandles
}

type KeyHandles struct {
	ekHandle  *tpm2.AuthHandle
	handle    *tpm2.AuthHandle
	srkHandle *tpm2.NamedHandle
}

func NewMember(tpm TPM) Member {
	var member = Member{
		tpm: &tpm,
	}

	return member
}

type Credential struct {
	A *FP256BN.ECP
	B *FP256BN.ECP
	C *FP256BN.ECP
	D *FP256BN.ECP
}

type Signature struct {
	c  *FP256BN.BIG
	c2 *FP256BN.BIG
	n  *FP256BN.BIG
	s  *FP256BN.BIG
	R  *FP256BN.ECP
	S  *FP256BN.ECP
	T  *FP256BN.ECP
	W  *FP256BN.ECP
	E  *FP256BN.ECP
}

func (member *Member) Sign(basename []byte, cred *Credential, rng *core.RAND) (*Signature, error) {
	hash := NewHash()
	hash.WriteBytes(basename)

	B, i, err := hash.HashToECP()

	if err != nil {
		return nil, err
	}

	numBuf := make([]byte, binary.MaxVarintLen32)
	binary.PutVarint(numBuf, int64(i))

	s2Buf := append(numBuf, basename[:]...)

	l := FP256BN.Random(rng)
	R := cred.A.Mul(l)
	S := cred.B.Mul(l)
	T := cred.C.Mul(l)
	W := cred.D.Mul(l)

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

	S2 := tpm2.TPM2BSensitiveData{
		Buffer: s2Buf,
	}

	Y2 := tpm2.TPM2BECCParameter{
		Buffer: yBuf[:],
	}

	/* run commit and get U */
	comRsp, err := (*member.tpm).Commit(member.keyHandles.handle, &P1, &S2, &Y2)

	if err != nil {
		return nil, fmt.Errorf("commit error: %v\n", err)
	}

	// get result (U)
	E := ParseECPFromTPMFmt(&comRsp.E.Point)

	hash = NewHash()
	hash.WriteECP(E, S)

	c2 := hash.SumToBIG()

	/* sign and get s1, n */
	var c2Bytes [32]byte
	c2.ToBytes(c2Bytes[:])

	sign, err := (*member.tpm).Sign(c2Bytes[:], comRsp.Counter, member.keyHandles.handle)

	if err != nil {
		return nil, fmt.Errorf("sign error: %v\n", err)
	}

	s1 := FP256BN.FromBytes(sign.Signature.Signature.ECDAA.SignatureS.Buffer)
	n := FP256BN.FromBytes(sign.Signature.Signature.ECDAA.SignatureR.Buffer)

	/* calc hash c1 = H( n | c2 ) */
	hash = NewHash()
	hash.WriteBIG(n)
	hash.WriteBytes(c2Bytes[:])
	c := hash.SumToBIG()

	signature := Signature{
		c:  c,
		s:  s1,
		R:  R,
		S:  S,
		T:  T,
		W:  W,
		n:  n,
		c2: c2,
		E:  E,
	}

	return &signature, nil
}

func Verify(basename []byte, signature *Signature, ipk *IPK) error {
	hash := NewHash()
	hash.WriteBytes(basename)

	B, _, err := hash.HashToECP()

	if err != nil {
		return err
	}

	hash = NewHash()

	// B^s
	tmp1 := FP256BN.NewECP()
	tmp1.Copy(B)
	tmp1 = tmp1.Mul(signature.s)

	// W ^ c
	tmp2 := FP256BN.NewECP()
	tmp2.Copy(signature.W)
	tmp2 = tmp2.Mul(signature.c)

	//  S^s W ^ (-c)
	tmp1.Sub(tmp2)
	hash.WriteECP(tmp1, signature.S)

	cDash := hash.SumToBIG()

	if FP256BN.Comp(signature.c2, cDash) != 0 {
		return fmt.Errorf("c is not match: %v != %v", signature.c, cDash)
	}

	a := FP256BN.Ate(ipk.Y, signature.R)
	b := FP256BN.Ate(g2(), signature.S)

	a = FP256BN.Fexp(a)
	b = FP256BN.Fexp(b)

	if !a.Equals(b) {
		return fmt.Errorf("Ate(ipk.Y, signature.R) != Ate(g2(), signature.S)")
	}

	tpm3 := FP256BN.NewECP()
	tpm3.Copy(signature.R)
	tpm3.Add(signature.W)

	c := FP256BN.Ate(g2(), signature.T)
	d := FP256BN.Ate(ipk.X, tpm3)

	c = FP256BN.Fexp(c)
	d = FP256BN.Fexp(d)

	if !c.Equals(d) {
		return fmt.Errorf("Ate(g2(), signature.T) != Ate(ipk.X, tpm3)")
	}

	return nil
}
