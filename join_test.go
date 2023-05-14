package ecdaa

import "testing"

func TestSW(t *testing.T) {
	rng := InitRandom()

	// seed, issuerB, err := GenJoinSeed(rng)

	// if err != nil {
	// 	t.Fatalf("%v", err)
	// }

	basename := []byte("basename")

	hash := newHash()
	hash.writeBytes(basename)
	B, _, _ := hash.hashToECP()

	req, _, err := GenJoinReq(basename, B, rng)

	if err != nil {
		t.Fatalf("%v", err)
	}

	err = VerifyJoinReq(req, basename, B)

	if err != nil {
		t.Fatalf("%v", err)
	}

}
