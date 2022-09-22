package main

import (
	"testing"
)

func TestAll(t *testing.T) {
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

	tmp := member
	member = NewMember(tpm)
	member.keyHandles = tmp.keyHandles

	cred, err := member.ActivateCredential(encCred, memberSession, &issuer.ipk)

	if err != nil {
		t.Fatalf("activate credential: %v", err)
	}

	signature, err := member.Sign(cred, rng)

	if err != nil {
		t.Fatalf("sign: %v", err)

	}

	err = Verify(signature, &issuer.ipk)

	if err != nil {
		t.Fatalf("verify: %v", err)

	}
}
