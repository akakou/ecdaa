package ecdaa

import (
	"miracl/core"

	"github.com/anonymous/ecdaa/tpm_utils"
)

func testIssuer(rng *core.RAND) (*Issuer, error) {
	issuer := RandomIssuer(rng)

	err := VerifyIPK(&issuer.Ipk)

	return &issuer, err
}

func ExampleInitialize(rng *core.RAND) (*Issuer, *SWSigner, error) {
	issuer, err := testIssuer(rng)
	if err != nil {
		return nil, nil, err
	}

	seed, issuerB, err := GenJoinSeed(rng)

	if err != nil {
		return nil, nil, err
	}

	req, sk, err := GenJoinReq(seed, rng)

	if err != nil {
		return nil, nil, err
	}

	err = VerifyJoinReq(req, seed, issuerB)

	if err != nil {
		return nil, nil, err
	}

	cred, err := issuer.MakeCred(req, issuerB, rng)

	if err != nil {
		return nil, nil, err
	}

	err = VerifyCred(cred, &issuer.Ipk)

	if err != nil {
		return nil, nil, err
	}

	randCred := RandomizeCred(cred, rng)
	err = VerifyCred(randCred, &issuer.Ipk)

	if err != nil {
		return nil, nil, err
	}

	signer := NewSWSigner(cred, sk)

	return issuer, &signer, nil
}

func ExampleTPMInitialize(tpm *tpm_utils.TPM, rng *core.RAND) (*Issuer, *TPMSigner, error) {
	issuer, err := testIssuer(rng)
	if err != nil {
		return nil, nil, err
	}

	seed, issuerB, err := GenJoinSeed(rng)
	if err != nil {
		return nil, nil, err
	}

	req, handle, err := GenJoinReqWithTPM(seed, tpm, rng)
	if err != nil {
		return nil, nil, err
	}

	cipherCred, _, err := issuer.MakeCredEncrypted(req, issuerB, rng)

	if err != nil {
		return nil, nil, err
	}

	cred, err := ActivateCredential(cipherCred, issuerB, req.JoinReq.Q, &issuer.Ipk, handle, tpm)

	if err != nil {
		return nil, nil, err
	}

	signer := NewTPMSigner(cred, handle, tpm)

	return issuer, &signer, nil
}
