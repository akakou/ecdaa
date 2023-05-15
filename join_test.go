package ecdaa

import "testing"

func TestSW(t *testing.T) {
	rng := InitRandom()
	issuer := RandomIssuer(rng)

	seed, issuerB, err := GenJoinSeed(rng)

	if err != nil {
		t.Fatalf("%v", err)
	}

	req, _, err := GenJoinReq(seed, rng)

	if err != nil {
		t.Fatalf("%v", err)
	}

	err = VerifyJoinReq(req, seed, issuerB)

	if err != nil {
		t.Fatalf("%v", err)
	}

	cred, err := issuer.MakeCred(req, issuerB, rng)

	if err != nil {
		t.Fatalf("%v", err)
	}

	err = VerifyCred(cred, &issuer.Ipk)

	if err != nil {
		t.Fatalf("%v", err)
	}
}
