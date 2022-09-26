package main

import (
	"encoding/binary"
	"fmt"
	"miracl/core"
	"miracl/core/FP256BN"

	"github.com/google/go-tpm/tpm2"
)

type Member struct {
	Tpm        *TPM
	KeyHandles *KeyHandles
}

type KeyHandles struct {
	EkHandle  *tpm2.AuthHandle
	SrkHandle *tpm2.NamedHandle
	Handle    *tpm2.AuthHandle
}

func NewMember(tpm TPM) Member {
	var member = Member{
		Tpm: &tpm,
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
	C      *FP256BN.BIG
	C2     *FP256BN.BIG
	N      *FP256BN.BIG
	SmallS *FP256BN.BIG
	R      *FP256BN.ECP
	S      *FP256BN.ECP
	T      *FP256BN.ECP
	W      *FP256BN.ECP
	E      *FP256BN.ECP
}

func (member *Member) Sign(basename []byte, cred *Credential, rng *core.RAND) (*Signature, error) {
	hash := newHash()
	hash.writeBytes(basename)

	B, i, err := hash.hashToECP()

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
	comRsp, err := (*member.Tpm).Commit(member.KeyHandles.Handle, &P1, &S2, &Y2)

	if err != nil {
		return nil, fmt.Errorf("commit error: %v\n", err)
	}

	// get result (U)
	E := ParseECPFromTPMFmt(&comRsp.E.Point)

	hash = newHash()
	hash.writeECP(E, S)

	c2 := hash.sumToBIG()

	/* sign and get s1, n */
	var c2Bytes [32]byte
	c2.ToBytes(c2Bytes[:])

	sign, err := (*member.Tpm).Sign(c2Bytes[:], comRsp.Counter, member.KeyHandles.Handle)

	if err != nil {
		return nil, fmt.Errorf("sign error: %v\n", err)
	}

	s1 := FP256BN.FromBytes(sign.Signature.Signature.ECDAA.SignatureS.Buffer)
	n := FP256BN.FromBytes(sign.Signature.Signature.ECDAA.SignatureR.Buffer)

	/* calc hash c1 = H( n | c2 ) */
	hash = newHash()
	hash.writeBIG(n)
	hash.writeBytes(c2Bytes[:])
	c := hash.sumToBIG()

	signature := Signature{
		C:      c,
		SmallS: s1,
		R:      R,
		S:      S,
		T:      T,
		W:      W,
		N:      n,
		C2:     c2,
		E:      E,
	}

	return &signature, nil
}

func Verify(basename []byte, signature *Signature, ipk *IPK) error {
	hash := newHash()
	hash.writeBytes(basename)

	B, _, err := hash.hashToECP()

	if err != nil {
		return err
	}

	hash = newHash()

	// B^s
	tmp1 := FP256BN.NewECP()
	tmp1.Copy(B)
	tmp1 = tmp1.Mul(signature.SmallS)

	// W ^ c
	tmp2 := FP256BN.NewECP()
	tmp2.Copy(signature.W)
	tmp2 = tmp2.Mul(signature.C)

	//  S^s W ^ (-c)
	tmp1.Sub(tmp2)
	hash.writeECP(tmp1, signature.S)

	cDash := hash.sumToBIG()

	if FP256BN.Comp(signature.C2, cDash) != 0 {
		return fmt.Errorf("c is not match: %v != %v", signature.C, cDash)
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
