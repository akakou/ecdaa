package main

import (
	"testing"
)

func TestNewIssuer(t *testing.T) {
	rng := InitRandom()

	issuer := RandomIssuer(rng)

	err := VerifyIPK(&issuer.ipk)

	if err != nil {
		t.Fatalf("%v", err)
	}
}
