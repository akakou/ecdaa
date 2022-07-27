package main

import (
	"fmt"
	"testing"
)

func TestJoin(t *testing.T) {
	rng := InitRandom()

	issuer := RandomIssuer(rng)
	seed := issuer.genSeedForJoin(rng)

	member := NewMember()
	_, err := member.genReqForJoin(seed, rng)
	if err != nil {
		t.Fatalf("%v", err)
	}

	fmt.Printf("m=%v, B=%v\n", seed.m, seed.B)

}
