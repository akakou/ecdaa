package main

import (
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
