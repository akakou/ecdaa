package main

type Member struct {
	tpm *TPM
}

func NewMember(tpm TPM) Member {
	var member = Member{
		tpm: &tpm,
	}

	return member
}
