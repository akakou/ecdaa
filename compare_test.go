package main

import (
	"miracl/core/FP256BN"
	"testing"
)

func TestCompECP(t *testing.T) {
	rng := InitRandom()

	big := FP256BN.Random(rng)

	x := g1()
	x = x.Mul(big)

	y := g1()

	if compECP(x, y) {
		t.Errorf("unexpected match (`%v, %v`)", x, y)
	}

	y = y.Mul(big)

	if !compECP(x, y) {
		t.Errorf("not match (`%v, %v`)", x, y)
	}
}
