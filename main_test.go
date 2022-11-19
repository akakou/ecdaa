package ecdaa

import (
	"testing"
)

func TestAll(t *testing.T) {
	message := []byte("hoge")
	basename := []byte("fuga")
	password := []byte("piyo")

	rng := InitRandom()

	tpm, err := OpenTPM(password, TPM_PATH)
	if err != nil {
		t.Errorf("%v", err)
	}
	defer tpm.Close()

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

	cipherCred, err := issuer.MakeCred(req, issuerSession, rng)

	if err != nil {
		t.Fatalf("%v", err)
	}

	cred, err := member.ActivateCredential(cipherCred, memberSession, &issuer.Ipk)

	if err != nil {
		t.Fatalf("activate credential: %v", err)
	}

	signature, err := member.Sign(message, basename, cred, rng)

	if err != nil {
		t.Fatalf("sign: %v", err)

	}

	err = Verify(message, basename, signature, &issuer.Ipk, RevocationList{})

	if err != nil {
		t.Fatalf("verify: %v", err)

	}
}
