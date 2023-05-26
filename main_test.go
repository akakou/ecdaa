package ecdaa

import "testing"

func TestTPM(t *testing.T) {
	message := []byte("hoge")
	incorrect_message := []byte("hoge2")

	basename := []byte("fuga")
	basename2 := []byte("fuga2")
	incorrect_basename := []byte("fuga3")

	password := []byte("piyo")

	rng := InitRandom()

	tpm, err := OpenTPM(password, TPM_PATH)
	if err != nil {
		t.Errorf("%v", err)
	}
	defer tpm.Close()

	issuer := RandomIssuer(rng)

	err = VerifyIPK(&issuer.Ipk)
	if err != nil {
		t.Errorf("%v", err)
	}

	seed, issuerB, err := GenJoinSeed(rng)
	if err != nil {
		t.Fatalf("%v", err)
	}

	req, handle, _, err := GenJoinReqWithTPM(seed, tpm, rng)
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

	signature, err := SignTPM(message, basename, cred, handle, tpm, rng)

	if err != nil {
		t.Fatalf("sign: %v", err)

	}

	same_bsn_signature, err := SignTPM(message, basename, cred, handle, tpm, rng)

	if err != nil {
		t.Fatalf("sign: %v", err)

	}

	not_same_bsn_signature, err := SignTPM(message, basename2, cred, handle, tpm, rng)

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

func TestSW(t *testing.T) {
	rng := InitRandom()
	issuer := RandomIssuer(rng)

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

	signature, err := Sign([]byte("hello"), []byte("hello"), sk, cred, rng)

	if err != nil {
		t.Fatalf("%v", err)
	}

	err = Verify([]byte("hello"), []byte("hello"), signature, &issuer.Ipk, RevocationList{})

	if err != nil {
		t.Fatalf("%v", err)
	}
}
