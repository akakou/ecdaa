package ecdaa

import (
	"bytes"
	"testing"

	"github.com/akakou-fork/amcl-go/miracl/core/FP256BN"

	"github.com/akakou-fork/amcl-go/miracl/core"
	amcl_utils "github.com/akakou/fp256bn-amcl-utils"

	"github.com/akakou/ecdaa/tpm_utils"
)

func TestEncodeDecodeIPK(t *testing.T) {
	rnd := amcl_utils.InitRandom()

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

	rnd := amcl_utils.InitRandom()

	cred.A = amcl_utils.RandomECP(rnd)
	cred.B = amcl_utils.RandomECP(rnd)
	cred.C = amcl_utils.RandomECP(rnd)
	cred.D = amcl_utils.RandomECP(rnd)

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

	rnd := amcl_utils.InitRandom()

	signature.Proof.SmallC = FP256BN.Random(rnd)
	signature.Proof.SmallN = FP256BN.Random(rnd)
	signature.Proof.SmallS = FP256BN.Random(rnd)

	signature.RandomizedCred.A = amcl_utils.RandomECP(rnd)
	signature.RandomizedCred.B = amcl_utils.RandomECP(rnd)
	signature.RandomizedCred.C = amcl_utils.RandomECP(rnd)
	signature.RandomizedCred.D = amcl_utils.RandomECP(rnd)
	signature.Proof.K = amcl_utils.RandomECP(rnd)

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

	rnd := amcl_utils.InitRandom()

	joinSeed.Basename = []byte("basename")
	joinSeed.S2 = amcl_utils.RandomBytes(rnd, 32)
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
	rnd := amcl_utils.InitRandom()

	joinRequest := JoinRequest{
		Proof: &SchnorrProof{
			SmallC: amcl_utils.RandomBig(rnd),
			SmallS: amcl_utils.RandomBig(rnd),
			SmallN: amcl_utils.RandomBig(rnd),
			K:      amcl_utils.RandomECP(rnd),
		},
		Q: amcl_utils.RandomECP(rnd),
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

	tpm, err := tpm_utils.OpenTPM(password, tpm_utils.TPM_PATH)
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
				SmallC: amcl_utils.RandomBig(rnd),
				SmallS: amcl_utils.RandomBig(rnd),
				SmallN: amcl_utils.RandomBig(rnd),
				K:      amcl_utils.RandomECP(rnd),
			},
			Q: amcl_utils.RandomECP(rnd),
		},
		EKCert:  cert,
		SrkName: amcl_utils.RandomBytes(rnd, 32),
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

	credCipher.WrappedCredential = amcl_utils.RandomBytes(rnd, 32)
	credCipher.IdObject = amcl_utils.RandomBytes(rnd, 32)
	credCipher.EncA = amcl_utils.RandomBytes(rnd, 32)
	credCipher.EncC = amcl_utils.RandomBytes(rnd, 32)
	credCipher.IV = amcl_utils.RandomBytes(rnd, 32)

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

	rnd := amcl_utils.InitRandom()
	rand := amcl_utils.RandomBig(rnd)

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
