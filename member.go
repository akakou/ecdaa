package main

import "miracl/core/FP256BN"

type Member struct {
	tpm *TPM
}

func NewMember(tpm TPM) Member {
	var member = Member{
		tpm: &tpm,
	}

	return member
}

type Credential struct {
	A *FP256BN.ECP
	B *FP256BN.ECP
	C *FP256BN.ECP
	D *FP256BN.ECP
}
