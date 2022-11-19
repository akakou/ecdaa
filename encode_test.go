package ecdaa

import (
	"bytes"
	"miracl/core"
	"miracl/core/FP256BN"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestEncodeDecodeIPK(t *testing.T) {
	rnd := InitRandom()

	isk := RandomISK(rnd)
	ipk := RandomIPK(&isk, rnd)

	encoded := ipk.Encode()
	decoded := encoded.Decode()

	if !ipk.X.Equals(decoded.X) {
		t.Fatalf("X is not equal")
	}

	if !ipk.Y.Equals(decoded.Y) {
		t.Fatalf("Y is not equal")
	}

	if ipk.C.ToString() != decoded.C.ToString() {
		t.Fatalf("C is not equal")
	}

	if ipk.SX.ToString() != decoded.SX.ToString() {
		t.Fatalf("SX is not equal")
	}

	if ipk.SY.ToString() != decoded.SY.ToString() {
		t.Fatalf("SY is not equal")
	}
}

func TestEncodeDecodeISK(t *testing.T) {
	isk := RandomISK(core.NewRAND())

	encoded := isk.Encode()
	decoded := encoded.Decode()

	if isk.X.ToString() != decoded.X.ToString() {
		t.Fatalf("X is not equal")
	}

	if isk.Y.ToString() != decoded.Y.ToString() {
		t.Fatalf("Y is not equal")
	}
}

func TestEncodeDecodeCredential(t *testing.T) {
	var cred Credential

	rnd := InitRandom()

	cred.A = randomECP(rnd)
	cred.B = randomECP(rnd)
	cred.C = randomECP(rnd)
	cred.D = randomECP(rnd)

	encoded := cred.Encode()
	decoded := encoded.Decode()

	if !cred.A.Equals(decoded.A) {
		t.Fatalf("A is not equal")
	}

	if !cred.B.Equals(decoded.B) {
		t.Fatalf("B is not equal")
	}

	if !cred.C.Equals(decoded.C) {
		t.Fatalf("C is not equal")
	}

	if !cred.D.Equals(decoded.D) {
		t.Fatalf("D is not equal")
	}
}

func TestEncodeDecodeSignature(t *testing.T) {
	var signature Signature

	rnd := InitRandom()

	signature.C = FP256BN.Random(rnd)
	signature.C2 = FP256BN.Random(rnd)
	signature.N = FP256BN.Random(rnd)
	signature.SmallS = FP256BN.Random(rnd)

	signature.R = randomECP(rnd)
	signature.S = randomECP(rnd)
	signature.T = randomECP(rnd)
	signature.W = randomECP(rnd)
	signature.E = randomECP(rnd)
	signature.K = randomECP(rnd)

	encoded := signature.Encode()
	decoded := encoded.Decode()

	if FP256BN.Comp(signature.C, decoded.C) != 0 {
		t.Fatalf("C is not equal")
	}

	if FP256BN.Comp(signature.C2, decoded.C2) != 0 {
		t.Fatalf("C2 is not equal")
	}

	if FP256BN.Comp(signature.N, decoded.N) != 0 {
		t.Fatalf("N is not equal")
	}

	if FP256BN.Comp(signature.SmallS, decoded.SmallS) != 0 {
		t.Fatalf("SmallS is not equal")
	}

	if !signature.R.Equals(decoded.R) {
		t.Fatalf("R is not equal")
	}

	if !signature.S.Equals(decoded.S) {
		t.Fatalf("S is not equal")
	}

	if !signature.T.Equals(decoded.T) {
		t.Fatalf("T is not equal")
	}

	if !signature.W.Equals(decoded.W) {
		t.Fatalf("W is not equal")
	}

	if !signature.E.Equals(decoded.E) {
		t.Fatalf("E is not equal")
	}

	if !signature.K.Equals(decoded.K) {
		t.Fatalf("K is not equal")
	}
}

func TestEncodeDecodeJoinSeeds(t *testing.T) {
	var joinSeeds JoinSeeds

	rnd := InitRandom()

	joinSeeds.Basename = []byte("basename")
	joinSeeds.S2 = randomBytes(rnd, 32)
	joinSeeds.Y2 = FP256BN.Random(rnd)

	encoded := joinSeeds.Encode()
	decoded := encoded.Decode()

	if !bytes.Equal(joinSeeds.Basename, decoded.Basename) {
		t.Fatalf("basename is not equal")
	}

	if !bytes.Equal(joinSeeds.S2, decoded.S2) {
		t.Fatalf("s2 is not equal")
	}

	if FP256BN.Comp(joinSeeds.Y2, decoded.Y2) != 0 {
		t.Fatalf("y2 is not equal")
	}
}

func TestEncodedDecodeJoinRequest(t *testing.T) {
	var joinRequest JoinRequest

	password := []byte("hoge")

	tpm, err := OpenTPM(password, TPM_PATH)
	defer tpm.Close()

	if err != nil {
		t.Errorf("%v", err)
	}

	cert, err := tpm.ReadEKCert()

	if err != nil {
		t.Errorf("%v", err)
	}

	rnd := core.NewRAND()

	joinRequest.EKCert = cert

	param := publicParams()

	joinRequest.Public = &tpm2.TPM2BPublic{
		PublicArea: param.key,
	}

	joinRequest.C1 = FP256BN.Random(rnd)
	joinRequest.S1 = FP256BN.Random(rnd)
	joinRequest.N = FP256BN.Random(rnd)
	joinRequest.Q = randomECP(rnd)
	joinRequest.SrkName = randomBytes(rnd, 32)

	encoded := joinRequest.Encode()
	decoded, err := encoded.Decode()

	if err != nil {
		t.Errorf("%v", err)
	}

	reEncoded, err := tpm2.Marshal(joinRequest.Public)

	if err != nil {
		t.Errorf("%v", err)
	}

	if !bytes.Equal(joinRequest.EKCert.RawIssuer, decoded.EKCert.RawIssuer) {
		t.Fatalf("EKCert is not equal")
	}

	if !bytes.Equal(
		encoded.Public,
		reEncoded) {
		t.Fatalf("Public is not equal")
	}

	if FP256BN.Comp(joinRequest.C1, decoded.C1) != 0 {
		t.Fatalf("C1 is not equal")
	}

	if FP256BN.Comp(joinRequest.S1, decoded.S1) != 0 {
		t.Fatalf("S1 is not equal")
	}

	if FP256BN.Comp(joinRequest.N, decoded.N) != 0 {
		t.Fatalf("N is not equal")
	}

	if !joinRequest.Q.Equals(decoded.Q) {
		t.Fatalf("Q is not equal")
	}

	if !bytes.Equal(joinRequest.SrkName, decoded.SrkName) {
		t.Fatalf("SrkName is not equal")
	}
}

func TestEncodedDecodeCredCipher(t *testing.T) {
	var credCipher CredCipher

	rnd := core.NewRAND()

	credCipher.WrappedCredential = randomBytes(rnd, 32)
	credCipher.IdObject = randomBytes(rnd, 32)
	credCipher.EncA = randomBytes(rnd, 32)
	credCipher.EncC = randomBytes(rnd, 32)
	credCipher.IV = randomBytes(rnd, 32)

	encoded := credCipher.Encode()
	decoded := encoded.Decode()

	if !bytes.Equal(credCipher.WrappedCredential, decoded.WrappedCredential) {
		t.Fatalf("WrappedCredential is not equal")
	}

	if !bytes.Equal(credCipher.IdObject, decoded.IdObject) {
		t.Fatalf("IdObject is not equal")
	}

	if !bytes.Equal(credCipher.EncA, decoded.EncA) {
		t.Fatalf("EncA is not equal")
	}

	if !bytes.Equal(credCipher.EncC, decoded.EncC) {
		t.Fatalf("EncC is not equal")
	}

	if !bytes.Equal(credCipher.IV, decoded.IV) {
		t.Fatalf("IV is not equal")
	}
}

func TestEncodedDecodeRL(t *testing.T) {
	var rl RevocationList

	rnd := InitRandom()
	rand := randomBig(rnd)

	rl = append(rl, rand)
	rl = append(rl, rand)

	encoded := EncodeRevocationList(rl)
	decoded := DecodeRevocationList(encoded)
	reencoded := EncodeRevocationList(decoded)

	for i := 0; i < len(rl); i++ {
		if !bytes.Equal(encoded[i], reencoded[i]) {
			t.Fatalf("Encoded/DecodeRL is not equal")
		}
	}
}
