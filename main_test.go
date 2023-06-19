package ecdaa

import (
	"miracl/core"
	"testing"

	"github.com/akakou/mcl_utils"

	"github.com/akakou/ecdaa/tpm_utils"
)

func testIssuer(t *testing.T, rng *core.RAND) *Issuer {
	issuer := RandomIssuer(rng)

	err := VerifyIPK(&issuer.Ipk)

	if err != nil {
		t.Fatalf("%v", err)
	}

	return &issuer
}

func TestTPM(t *testing.T) {
	rng := mcl_utils.InitRandom()
	issuer := testIssuer(t, rng)

	password := []byte("piyo")

	tpm, err := tpm_utils.OpenTPM(password, tpm_utils.TPM_PATH)
	if err != nil {
		t.Errorf("%v", err)
	}
	defer tpm.Close()

	seed, issuerB, err := GenJoinSeed(rng)
	if err != nil {
		t.Fatalf("%v", err)
	}

	req, handle, err := GenJoinReqWithTPM(seed, tpm, rng)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cipherCred, _, err := issuer.MakeCredEncrypted(req, issuerB, rng)

	if err != nil {
		t.Fatalf("%v", err)
	}

	cred, err := ActivateCredential(cipherCred, issuerB, req.JoinReq.Q, &issuer.Ipk, handle, tpm)

	if err != nil {
		t.Fatalf("activate credential: %v", err)
	}

	signer := NewTPMSigner(cred, handle, tpm)
	testSignAndVerify(t, &signer, issuer)
}

func TestSW(t *testing.T) {
	rng := mcl_utils.InitRandom()
	issuer := testIssuer(t, rng)

	seed, issuerB, err := GenJoinSeed(rng)

	if err != nil {
		t.Fatalf("%v", err)
	}

	req, sk, err := GenJoinReq(seed, rng)

	if err != nil {
		t.Fatalf("%v", err)
	}

	err = VerifyJoinReq(req, seed, issuerB)

	if err != nil {
		t.Fatalf("%v", err)
	}

	cred, err := issuer.MakeCred(req, issuerB, rng)

	if err != nil {
		t.Fatalf("%v", err)
	}

	err = VerifyCred(cred, &issuer.Ipk)

	if err != nil {
		t.Fatalf("%v", err)
	}

	randCred := RandomizeCred(cred, rng)
	err = VerifyCred(randCred, &issuer.Ipk)

	if err != nil {
		t.Fatalf("%v", err)
	}

	signer := NewSWSigner(cred, sk)
	testSignAndVerify(t, &signer, issuer)
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
