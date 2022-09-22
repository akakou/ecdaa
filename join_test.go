package main

import (
	"miracl/core/FP256BN"
	"testing"
)

func TestJoinWithReal(t *testing.T) {
	rng := InitRandom()

	tpm, err := OpenRealTPM()
	if err != nil {
		t.Errorf("%v", err)
	}

	issuer := RandomIssuer(rng)

	err = VerifyIPK(&issuer.ipk)
	if err != nil {
		t.Errorf("%v", err)
	}

	seed, issuerSession, err := issuer.GenSeedForJoin(rng)
	if err != nil {
		t.Fatalf("%v", err)
	}

	member := NewMember(tpm)
	req, memberSession, err := member.GenReqForJoin(seed, rng)
	if err != nil {
		t.Fatalf("%v", err)
	}
	tpm.Close()

	encCred, err := issuer.MakeCred(req, issuerSession, rng)

	if err != nil {
		t.Fatalf("%v", err)
	}

	tpm, err = OpenRealTPM()
	if err != nil {
		t.Errorf("%v", err)
	}

	member = NewMember(tpm)

	cred, err := member.ActivateCredential(encCred, memberSession, &issuer.ipk)

	if err != nil {
		t.Fatalf("activate credential: %v", err)
	}

	if FP256BN.Comp(cred.A.GetX(), issuerSession.cred.A.GetX()) != 0 || FP256BN.Comp(cred.A.GetY(), issuerSession.cred.A.GetY()) != 0 {
		t.Fatalf("cred not match: %v %v", *cred.A, *issuerSession.cred.A)
	}

	if FP256BN.Comp(cred.C.GetX(), issuerSession.cred.C.GetX()) != 0 || FP256BN.Comp(cred.C.GetY(), issuerSession.cred.C.GetY()) != 0 {
		t.Fatalf("cred not match: %v %v", *cred.C, *issuerSession.cred.C)
	}
}

// func TestJoinWithSW(t *testing.T) {
// 	rng := InitRandom()

// 	tpm := NewSWTPM(rng)
// 	defer tpm.Close()

// 	issuer := RandomIssuer(rng)
// 	seed, session, err := issuer.genSeedForJoin(rng)
// 	if err != nil {
// 		t.Fatalf("%v", err)
// 	}

// 	member := NewMember(tpm)
// 	req, err := member.genReqForJoin(seed, rng)
// 	if err != nil {
// 		t.Fatalf("%v", err)
// 	}

// 	_, err = issuer.MakeCred(req, session, rng)

// 	if err != nil {
// 		t.Fatalf("%v", err)
// 	}
// }
