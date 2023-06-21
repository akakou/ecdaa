package ecdaa_bench

import (
	"encoding/hex"
	"testing"

	"github.com/akakou/ecdaa"
	"github.com/akakou/ecdaa/tpm_utils"
	"github.com/akakou/mcl_utils"
)

var password = []byte("piyo")

func setupTpmSigner(tpm *tpm_utils.TPM, b *testing.B) (*ecdaa.Credential, *ecdaa.KeyHandles) {
	rng := mcl_utils.InitRandom()
	issuer := testIssuer(b, rng)

	seed, issuerB, err := ecdaa.GenJoinSeed(rng)
	checkError(err, b)

	req, handle, err := ecdaa.GenJoinReqWithTPM(seed, tpm, rng)
	checkError(err, b)

	cipherCred, _, err := issuer.MakeCredEncrypted(req, issuerB, rng)
	checkError(err, b)

	cred, err := ecdaa.ActivateCredential(cipherCred, issuerB, req.JoinReq.Q, &issuer.Ipk, handle, tpm)
	checkError(err, b)

	return cred, handle
}

func BenchmarkSign(b *testing.B) {
	tpm, err := tpm_utils.OpenTPM(password, tpm_utils.TPM_PATH)
	checkError(err, b)
	defer tpm.Close()

	rng := mcl_utils.InitRandom()
	cred, handle := setupTpmSigner(tpm, b)

	basename, err := hex.DecodeString("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
	checkError(err, b)

	signer := ecdaa.NewTPMSigner(cred, handle, tpm)
	b.Run("tpm_sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			signer.Sign([]byte{}, basename, rng)
		}
	})
}
