package ecdaa

import (
	"testing"

	"github.com/akakou/ecdaa/tpm_utils"
	"github.com/akakou/mcl_utils"
)

func TestTPM(t *testing.T) {
	rng := mcl_utils.InitRandom()
	password := []byte("piyo")

	tpm, err := tpm_utils.OpenTPM(password, tpm_utils.TPM_PATH)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer tpm.Close()

	issuer, signer, err := ExampleTPMInitialize(tpm, rng)
	if err != nil {
		t.Fatalf("%v", err)
	}

	testSignAndVerify(t, signer, issuer)
}

func TestSW(t *testing.T) {
	rng := mcl_utils.InitRandom()

	issuer, signer, err := ExampleInitialize(rng)
	if err != nil {
		t.Errorf("%v", err)
	}

	testSignAndVerify(t, signer, issuer)
}

func testSignAndVerify(t *testing.T, signer Signer, issuer *Issuer) {
	message := []byte("hoge")
	incorrect_message := []byte("hoge2")

	basename := []byte("fuga")
	basename2 := []byte("fuga2")
	incorrect_basename := []byte("fuga3")

	rng := mcl_utils.InitRandom()

	signature, err := signer.Sign(message, basename, rng)

	if err != nil {
		t.Fatalf("sign: %v", err)

	}

	same_bsn_signature, err := signer.Sign(message, basename, rng)

	if err != nil {
		t.Fatalf("sign: %v", err)

	}

	not_same_bsn_signature, err := signer.Sign(message, basename2, rng)

	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	t.Run("verify_signature_correct", func(t *testing.T) {
		// fmt.Print("sign_correct...\n")
		err = Verify(message, basename, signature, &issuer.Ipk, RevocationList{})

		if err != nil {
			t.Fatalf("verify: %v", err)
		}

	})

	t.Run("verify_signature_msg_incorrect", func(t *testing.T) {
		// fmt.Print("sign_msg_incorrect...\n")
		err = Verify(incorrect_message, basename, signature, &issuer.Ipk, RevocationList{})

		if err == nil {
			t.Fatalf("verify: incorrect judge, msg is incorrect but verify say valid")
		}
	})

	t.Run("verify_signature_bsn_incorrect", func(t *testing.T) {
		// fmt.Print("sign_bsn_incorrect...\n")
		err = Verify(message, incorrect_basename, signature, &issuer.Ipk, RevocationList{})

		if err == nil {
			t.Fatalf("verify: incorrect judge, basename is incorrect but verify say valid")
		}
	})

	t.Run("signing_are_same_k", func(t *testing.T) {
		if !signature.Proof.K.Equals(same_bsn_signature.Proof.K) {
			t.Fatalf("wrong that, Ks which are made by same base name are not same.")
		}
	})

	t.Run("signing_are_not_same k", func(t *testing.T) {
		if signature.Proof.K.Equals(not_same_bsn_signature.Proof.K) {
			t.Fatalf("wrong that, Ks which are made by same base name are same.")
		}
	})
}
