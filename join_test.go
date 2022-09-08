package main

import (
	"testing"
)

func TestJoin(t *testing.T) {
	tpm, err := OpenRealTPM()
	defer tpm.Close()

	if err != nil {
		t.Errorf("%v", err)
	}

	rng := InitRandom()

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
