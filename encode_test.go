package ecdaa

import (
	"bytes"
	"miracl/core"
	"miracl/core/FP256BN"
	"testing"
)

func TestEncodeDecodeIPK(t *testing.T) {
	rnd := InitRandom()

	isk := RandomISK(rnd)
	ipk := RandomIPK(&isk, rnd)

	encoded, _ := ipk.Encode()

	decoded := IPK{}
	decoded.Decode(encoded)

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

	encoded, _ := isk.Encode()

	decoded := ISK{}
	decoded.Decode(encoded)

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

	encoded, _ := cred.Encode()
	decoded := Credential{}
	_ = decoded.Decode(encoded)

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
	signature.Proof = &SchnorrProof{}
	signature.RandomizedCred = &Credential{}

	rnd := InitRandom()

	signature.Proof.SmallC = FP256BN.Random(rnd)
	signature.Proof.SmallN = FP256BN.Random(rnd)
	signature.Proof.SmallS = FP256BN.Random(rnd)

	signature.RandomizedCred.A = randomECP(rnd)
	signature.RandomizedCred.B = randomECP(rnd)
	signature.RandomizedCred.C = randomECP(rnd)
	signature.RandomizedCred.D = randomECP(rnd)
	signature.Proof.K = randomECP(rnd)

	encoded, _ := signature.Encode()
	decoded := Signature{}
	decoded.Decode(encoded)

	if FP256BN.Comp(signature.Proof.SmallC, decoded.Proof.SmallC) != 0 {
		t.Fatalf("C is not equal")
	}

	if FP256BN.Comp(signature.Proof.SmallN, decoded.Proof.SmallN) != 0 {
		t.Fatalf("N is not equal")
	}

	if FP256BN.Comp(signature.Proof.SmallS, decoded.Proof.SmallS) != 0 {
		t.Fatalf("SmallS is not equal")
	}

	if !signature.RandomizedCred.A.Equals(decoded.RandomizedCred.A) {
		t.Fatalf("R is not equal")
	}

	if !signature.RandomizedCred.B.Equals(decoded.RandomizedCred.B) {
		t.Fatalf("S is not equal")
	}

	if !signature.RandomizedCred.C.Equals(decoded.RandomizedCred.C) {
		t.Fatalf("T is not equal")
	}

	if !signature.RandomizedCred.D.Equals(decoded.RandomizedCred.D) {
		t.Fatalf("W is not equal")
	}

	if !signature.Proof.K.Equals(decoded.Proof.K) {
		t.Fatalf("K is not equal")
	}
}

func TestEncodeDecodeJoinSeeds(t *testing.T) {
	var joinSeed JoinSeed

	rnd := InitRandom()

	joinSeed.Basename = []byte("basename")
	joinSeed.S2 = randomBytes(rnd, 32)
	joinSeed.Y2 = FP256BN.Random(rnd)

	encoded, _ := joinSeed.Encode()
	decoded := JoinSeed{}
	decoded.Decode(encoded)

	if !bytes.Equal(joinSeed.Basename, decoded.Basename) {
		t.Fatalf("basename is not equal")
	}

	if !bytes.Equal(joinSeed.S2, decoded.S2) {
		t.Fatalf("s2 is not equal")
	}

	if FP256BN.Comp(joinSeed.Y2, decoded.Y2) != 0 {
		t.Fatalf("y2 is not equal")
	}
}

func TestEncodedDecodeJoinRequest(t *testing.T) {
	rnd := InitRandom()

	joinRequest := JoinRequest{
		Proof: &SchnorrProof{
			SmallC: randomBig(rnd),
			SmallS: randomBig(rnd),
			SmallN: randomBig(rnd),
			K:      randomECP(rnd),
		},
		Q: randomECP(rnd),
	}

	encoded, _ := joinRequest.Encode()
	decoded := JoinRequest{}
	decoded.Decode(encoded)

	if FP256BN.Comp(joinRequest.Proof.SmallC, decoded.Proof.SmallC) != 0 {
		t.Fatalf("C is not equal")
	}

	if FP256BN.Comp(joinRequest.Proof.SmallN, decoded.Proof.SmallN) != 0 {
		t.Fatalf("N is not equal")
	}

	if FP256BN.Comp(joinRequest.Proof.SmallS, decoded.Proof.SmallS) != 0 {
		t.Fatalf("SmallS is not equal")
	}

	if !joinRequest.Q.Equals(decoded.Q) {
		t.Fatalf("Q is not equal")
	}

	if !joinRequest.Proof.K.Equals(decoded.Proof.K) {
		t.Fatalf("K is not equal")
	}
}

func TestEncodedDecodeJoinRequestTPM(t *testing.T) {
	password := []byte("hoge")

	tpm, err := OpenTPM(password, TPM_PATH)
	defer tpm.Close()

	if err != nil {
		t.Fatalf("%v", err)
	}

	cert, err := tpm.ReadEKCert()

	if err != nil {
		t.Fatalf("%v", err)
	}

	rnd := core.NewRAND()

	joinRequestTpm := JoinRequestTPM{
		JoinReq: &JoinRequest{
			Proof: &SchnorrProof{
				SmallC: randomBig(rnd),
				SmallS: randomBig(rnd),
				SmallN: randomBig(rnd),
				K:      randomECP(rnd),
			},
			Q: randomECP(rnd),
		},
		EKCert:  cert,
		SrkName: randomBytes(rnd, 32),
	}

	encoded, err := joinRequestTpm.Encode()
	decoded := JoinRequestTPM{}
	decoded.Decode(encoded)

	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(joinRequestTpm.EKCert.RawIssuer, decoded.EKCert.RawIssuer) {
		t.Fatalf("EKCert is not equal")
	}

	if FP256BN.Comp(joinRequestTpm.JoinReq.Proof.SmallC, decoded.JoinReq.Proof.SmallC) != 0 {
		t.Fatalf("C1 is not equal")
	}

	if FP256BN.Comp(joinRequestTpm.JoinReq.Proof.SmallS, decoded.JoinReq.Proof.SmallS) != 0 {
		t.Fatalf("S1 is not equal")
	}

	if FP256BN.Comp(joinRequestTpm.JoinReq.Proof.SmallN, decoded.JoinReq.Proof.SmallN) != 0 {
		t.Fatalf("N is not equal")
	}

	if !joinRequestTpm.JoinReq.Q.Equals(decoded.JoinReq.Q) {
		t.Fatalf("Q is not equal")
	}

	if !bytes.Equal(joinRequestTpm.SrkName, decoded.SrkName) {
		t.Fatalf("SrkName is not equal")
	}

	if !joinRequestTpm.JoinReq.Proof.K.Equals(decoded.JoinReq.Proof.K) {
		t.Fatalf("K is not equal")
	}
}

func TestEncodedDecodeCredCipher(t *testing.T) {
	var credCipher CredentialCipher

	rnd := core.NewRAND()

	credCipher.WrappedCredential = randomBytes(rnd, 32)
	credCipher.IdObject = randomBytes(rnd, 32)
	credCipher.EncA = randomBytes(rnd, 32)
	credCipher.EncC = randomBytes(rnd, 32)
	credCipher.IV = randomBytes(rnd, 32)

	encoded, _ := credCipher.Encode()
	decoded := CredentialCipher{}
	decoded.Decode(encoded)

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
