package main

import (
	"fmt"
	"testing"
)

func TestJoin(t *testing.T) {
	rng := InitRandom()

	issuer := RandomIssuer(rng)
	seed := issuer.genSeedForJoin(rng)

	fmt.Printf("m=%v, B=%v\n", seed.m, seed.B)

}
