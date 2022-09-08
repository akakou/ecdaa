package main

import (
	"fmt"
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
	// rng := InitRandom()
	basename := []byte("")

	/* create key a */
	sk := FP256BN.NewBIGint(2)
	// sk := FP256BN.Random(rng)

	// the public key is named "Q"
	/* calc hash */
	hash := NewHash()
	hash.WriteBytes(basename)

	B, _, err := hash.HashToECP()

	fmt.Printf("B=%v\n", B.ToString())

	if err != nil {
		t.Errorf("%v", err)
	}

	/* commit */
	r1 := FP256BN.NewBIGint(3)

	K := B.Mul(sk)
	E := B.Mul(r1)

	fmt.Printf("K=%v\n", K.ToString())
	fmt.Printf("E=%v\n", E.ToString())

	Q := K
	U1 := E

	/* calc hash c2 = H( U1 | P1 | Q | m ) */
	hash = NewHash()
	hash.WriteECP(U1, B, Q)
	c2 := hash.SumToBIG()

	fmt.Printf("c2=%v\n", c2.ToString())

	/* sign and get s1, n */
	n := FP256BN.NewBIGint(4)

	hash = NewHash()
	hash.WriteBIG(n, c2)
	c1 := hash.SumToBIG()

	s1 := FP256BN.Modmul(c1, sk, p())
	s1 = FP256BN.Modadd(r1, s1, p())
	
	fmt.Printf("c1=%v\n", c1.ToString())
	fmt.Printf("s1=%v\n", s1.ToString())

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
