package main

import (
	"testing"
)

func TestAll(t *testing.T) {
	rng := InitRandom()

	isk := RandomISK(rng)
	ipk := RandomIPK(&isk, rng)

	err := VerifyIPK(&ipk)
	if err != nil {
		t.Errorf("error: %v", err)
	}
}
