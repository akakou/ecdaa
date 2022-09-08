package main

import (
	"miracl/core/FP256BN"
	"testing"
)

func TestJoinWithReal(t *testing.T) {
	rng := InitRandom()

	tpm, err := OpenRealTPM()
	defer tpm.Close()

	if err != nil {
		t.Errorf("%v", err)
	}

	issuer := RandomIssuer(rng)
	seed, err := issuer.genSeedForJoin(rng)
	if err != nil {
		t.Fatalf("%v", err)
	}

	member := NewMember(tpm)
	_, err = member.genReqForJoin(seed, rng)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestJoinWithSW(t *testing.T) {
	rng := InitRandom()

	tpm := NewSWTPM(rng)
	defer tpm.Close()

	issuer := RandomIssuer(rng)
	seed, err := issuer.genSeedForJoin(rng)
	if err != nil {
		t.Fatalf("%v", err)
	}

	member := NewMember(tpm)
	_, err = member.genReqForJoin(seed, rng)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestJoinTmp(t *testing.T) {
	rng := InitRandom()
	basename := []byte("")

	/* create key a */
	sk := FP256BN.Random(rng)

	// the public key is named "Q"
	/* calc hash */
	hash := NewHash()
	hash.WriteBytes(basename)

	B, _, err := hash.HashToECP()

	if err != nil {
		t.Errorf("%v", err)
	}

	/* commit */
	r1 := FP256BN.Random(rng)

	K := B.Mul(sk)
	E := B.Mul(r1)

	Q := K
	U1 := E

	/* calc hash c2 = H( U1 | P1 | Q | m ) */
	hash = NewHash()
	hash.WriteECP(U1, B, Q)
	c2 := hash.SumToBIG()

	/* sign and get s1, n */
	n := FP256BN.Random(rng)

	hash = NewHash()
	hash.WriteBIG(n, c2)
	c1 := hash.SumToBIG()

	s1 := FP256BN.Modmul(c1, sk, p())
	s1 = FP256BN.Modadd(r1, s1, p())

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
		t.Errorf("U is not match (`%v` != `%v`)", U1.ToString(), UDashTmp.ToString())
	}
}
