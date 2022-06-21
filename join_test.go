package main

import (
	"fmt"
	"testing"
)

func TestJoin(t *testing.T) {
	rng := InitRandom()

	issuer := RandomIssuer(rng)
	seed := issuer.gen_seed_for_join(rng)

	fmt.Printf("m=%v, B=%v\n", seed.m, seed.B)

}
