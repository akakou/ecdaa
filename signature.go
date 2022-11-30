package ecdaa

import (
	"encoding/binary"
	"fmt"
	"miracl/core"
	"miracl/core/FP256BN"

	"github.com/google/go-tpm/tpm2"
)

type RevocationList = []*FP256BN.BIG

type Member struct {
	Tpm        *TPM
	KeyHandles *KeyHandles
}

type KeyHandles struct {
	EkHandle  *tpm2.AuthHandle
	SrkHandle *tpm2.NamedHandle
	Handle    *tpm2.AuthHandle
}

func NewMember(tpm *TPM) Member {
	var member = Member{
		Tpm: tpm,
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
	SmallC *FP256BN.BIG
	SmallN *FP256BN.BIG
	SmallS *FP256BN.BIG
	R      *FP256BN.ECP
	S      *FP256BN.ECP
	T      *FP256BN.ECP
	W      *FP256BN.ECP
	K      *FP256BN.ECP
}

func (member *Member) Sign(message, basename []byte, cred *Credential, rng *core.RAND) (*Signature, error) {
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

	xBuf := bigToBytes(S.GetX())
	yBuf := bigToBytes(S.GetY())

	P1 := tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{
			Buffer: xBuf,
		},
		Y: tpm2.TPM2BECCParameter{
			Buffer: yBuf,
		},
	}

	S2 := tpm2.TPM2BSensitiveData{
		Buffer: s2Buf,
	}

	Y2 := tpm2.TPM2BECCParameter{
		Buffer: bigToBytes(B.GetY()),
	}

	/* run commit and get U */
	comRsp, err := (*member.Tpm).Commit(member.KeyHandles.Handle, &P1, &S2, &Y2)

	if err != nil {
		return nil, fmt.Errorf("commit error: %v\n", err)
	}

	// get result (U)
	E := parseECPFromTPMFmt(&comRsp.E.Point)
	L := parseECPFromTPMFmt(&comRsp.L.Point)
	K := parseECPFromTPMFmt(&comRsp.K.Point)

	// c2 = H(E, S, W, L, K, g2, basename, message)
	hash = newHash()
	hash.writeECP(E, S, W, L, K)
	hash.writeECP2(g2())
	hash.writeBytes(basename, message)

	c2 := hash.sumToBIG()

	/* sign and get s1, n */
	c2Buf := bigToBytes(c2)

	sign, err := (*member.Tpm).Sign(c2Buf, comRsp.Counter, member.KeyHandles.Handle)

	if err != nil {
		return nil, fmt.Errorf("sign error: %v\n", err)
	}

	s1 := FP256BN.FromBytes(sign.Signature.Signature.ECDAA.SignatureS.Buffer)
	n := FP256BN.FromBytes(sign.Signature.Signature.ECDAA.SignatureR.Buffer)

	/* calc hash c = H( n | c2 ) */
	hash = newHash()
	hash.writeBIG(n)
	hash.writeBytes(c2Buf)
	c := hash.sumToBIG()

	signature := Signature{
		SmallC: c,
		SmallS: s1,
		R:      R,
		S:      S,
		T:      T,
		W:      W,
		SmallN: n,
		K:      K,
	}

	return &signature, nil
}

func Verify(message, basename []byte, signature *Signature, ipk *IPK, rl RevocationList) error {
	hash := newHash()
	hash.writeBytes(basename)

	B, _, err := hash.hashToECP()

	if err != nil {
		return err
	}

	hash = newHash()

	// E = S^s
	E := FP256BN.NewECP()
	E.Copy(signature.S)
	E = E.Mul(signature.SmallS)

	// E = W ^ c
	tmp2 := FP256BN.NewECP()
	tmp2.Copy(signature.W)
	tmp2 = tmp2.Mul(signature.SmallC)

	//  E = S^s W ^ (-c)
	E.Sub(tmp2)

	// L = s * P2
	L := B.Mul(signature.SmallS)

	// c * K
	tmp3 := signature.K.Mul(signature.SmallC)
	L.Sub(tmp3)

	// c' = H(E, S, W, L, K, g2, basename, message)
	hash.writeECP(E, signature.S, signature.W, L, signature.K)
	hash.writeECP2(g2())
	hash.writeBytes(basename, message)

	cDash := hash.sumToBIG()

	// c = H( n | c' )
	cDashBuf := bigToBytes(cDash)

	hash = newHash()
	hash.writeBIG(signature.SmallN)
	hash.writeBytes(cDashBuf)

	c := hash.sumToBIG()

	if FP256BN.Comp(signature.SmallC, c) != 0 {
		return fmt.Errorf("c is not match: %v != %v", signature.SmallC, c)
	}

	// check e(Y, R) == e(g_2, S)
	a := FP256BN.Ate(ipk.Y, signature.R)
	b := FP256BN.Ate(g2(), signature.S)

	a = FP256BN.Fexp(a)
	b = FP256BN.Fexp(b)

	if !a.Equals(b) {
		return fmt.Errorf("Ate(ipk.Y, signature.R) != Ate(g2(), signature.S)")
	}

	// check e(g2, T) == e(X, R W)
	tpm3 := FP256BN.NewECP()
	tpm3.Copy(signature.R)
	tpm3.Add(signature.W)

	d := FP256BN.Ate(g2(), signature.T)
	e := FP256BN.Ate(ipk.X, tpm3)

	d = FP256BN.Fexp(d)
	e = FP256BN.Fexp(e)

	if !d.Equals(e) {
		return fmt.Errorf("Ate(g2(), signature.T) != Ate(ipk.X, tpm3)")
	}

	for _, revoked := range rl {
		tmp4 := FP256BN.NewECP()
		tmp4.Copy(signature.S)
		tmp4 = tmp4.Mul(revoked)

		if signature.W == tmp4 {
			return fmt.Errorf("the secret key revoked")
		}
	}

	return nil
}
