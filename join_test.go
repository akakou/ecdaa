package ecdaa

import "testing"

func TestSW(t *testing.T) {
	rng := InitRandom()

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

}
