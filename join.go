package main

import (
	"crypto/x509"
	"miracl/core"
	"miracl/core/FP256BN"

	"github.com/google/go-tpm/tpm2"
)

type JoinSeeds struct {
	m *FP256BN.BIG
	B *FP256BN.ECP
}

type JoinRequest struct {
	public *tpm2.Public
	cert   *x509.Certificate
}

/**
 * Step1. generate seed for join (by Issuer)
 */
func (_ *Issuer) genSeedForJoin(rng *core.RAND) *JoinSeeds {
	var seed JoinSeeds

	m := FP256BN.Random(rng)
	B := HashFromBIGToECP(m)

	seed.m = m
	seed.B = B

	return &seed
}

/**
 * Step2. generate request for join (by Member)
 */
func (_ *Member) genReqForJoin(seeds *JoinSeeds, rng *core.RAND) (*JoinRequest, error) {
	var req JoinRequest
	// pub, err := CreateKey()

	// if err != nil {
	// 	return nil, err
	// }

	// cert, err = ReadEKCert()

	// if err != nil {
	// 	return nil, err
	// }

	// req.cert = cert

	return &req, nil
}

// /**
//  * Step3. make credential for join (by Issuer)
//  */
// func (_ *Member) make_cred(n FP256BN.BIG, rng *core.RAND) JoinRequest {
// 	var req JoinRequest

// 	return req
// }

// /**
//  * Step4. activate credential for join with TPM2_activate_credential (by Member)
//  */
// func (_ *Member) activate_cred(n FP256BN.BIG, rng *core.RAND) JoinRequest {
// 	var req JoinRequest

// 	return req
// }
