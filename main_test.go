package ecdaa

import (
	"testing"
)

func TestAll(t *testing.T) {
	message := []byte("hoge")
	incorrect_message := []byte("hoge2")

	basename := []byte("fuga")
	incorrect_basename := []byte("fuga2")

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

	seed, issuerSession, err := issuer.GenSeedForJoin(rng)
	if err != nil {
		t.Fatalf("%v", err)
	}

	member := NewMember(tpm)
	req, memberSession, err := member.GenReqForJoin(seed, rng)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cipherCred, err := issuer.MakeCred(req, issuerSession, rng)

	if err != nil {
		t.Fatalf("%v", err)
	}

	cred, err := member.ActivateCredential(cipherCred, memberSession, &issuer.Ipk)

	if err != nil {
		t.Fatalf("activate credential: %v", err)
	}

	signature, err := member.Sign(message, basename, cred, rng)

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
}
