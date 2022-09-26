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

	err = VerifyIPK(&issuer.Ipk)
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
	member.KeyHandles = tmp.KeyHandles

	cred, err := member.ActivateCredential(encCred, memberSession, &issuer.Ipk)

	if err != nil {
		t.Fatalf("activate credential: %v", err)
	}

	signature, err := member.Sign([]byte("hoge"), cred, rng)

	if err != nil {
		t.Fatalf("sign: %v", err)

	}

	err = Verify([]byte("hoge"), signature, &issuer.Ipk)

	if err != nil {
		t.Fatalf("verify: %v", err)

	}
}
