package main

import (
	"testing"
)

func TestNewIssuer(t *testing.T) {
	rng := InitRandom()

	issuer := RandomIssuer(rng)

	err := VerifyIPK(&issuer.Ipk)

	if err != nil {
		t.Fatalf("%v", err)
	}
}
