package ecdaa_bench

import (
	"encoding/hex"
	"testing"

	_acml "github.com/akakou/fp256bn-amcl-utils"

	"github.com/akakou/ecdaa"
	_tpm "github.com/akakou/ecdaa/tpm"
)

var password = []byte("piyo")

func BenchmarkSignTPM(b *testing.B) {
	tpm, err := _tpm.OpenTPM(password, _tpm.TPM_PATH)
	checkError(err, b)
	defer tpm.Close()

	rng := _acml.InitRandom()
	_, signer, err := ecdaa.ExampleTPMInitialize(tpm, rng)
	checkError(err, b)

	basename, err := hex.DecodeString("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b98242cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7")
	checkError(err, b)

	b.Run("tpm_sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			signer.Sign([]byte{}, basename, rng)
		}
	})
}
