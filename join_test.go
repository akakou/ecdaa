package main

import (
	"testing"
)

func TestJoin(t *testing.T) {
	rng := InitRandom()

	issuer := RandomIssuer(rng)
	seed, err := issuer.genSeedForJoin(rng)
	if err != nil {
		t.Fatalf("%v", err)
	}

	member := NewMember()
	_, err = member.genReqForJoin(seed, rng)
	if err != nil {
		t.Fatalf("%v", err)
	}
}
