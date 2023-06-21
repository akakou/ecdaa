package ecdaa_bench

import (
	"encoding/hex"
	"testing"

	"github.com/akakou/ecdaa"
	"github.com/akakou/ecdaa/tpm_utils"
	"github.com/akakou/mcl_utils"
)

var password = []byte("piyo")

func BenchmarkSignTPM(b *testing.B) {
	tpm, err := tpm_utils.OpenTPM(password, tpm_utils.TPM_PATH)
	checkError(err, b)
	defer tpm.Close()

	rng := mcl_utils.InitRandom()
	_, signer, err := ecdaa.ExampleTPMInitialize(tpm, rng)
	checkError(err, b)

	basename, err := hex.DecodeString("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
	checkError(err, b)

	b.Run("tpm_sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			signer.Sign([]byte{}, basename, rng)
		}
	})
}
