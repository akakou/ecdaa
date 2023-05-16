package ecdaa

import (
	"crypto/x509"
	"miracl/core/FP256BN"
)

type MiddleEncodedISK struct {
	X []byte
	Y []byte
}

func (isk *ISK) Encode() *MiddleEncodedISK {
	var encoded MiddleEncodedISK

	encoded.X = bigToBytes(isk.X)
	encoded.Y = bigToBytes(isk.Y)

	return &encoded
}

func (encoded *MiddleEncodedISK) Decode() *ISK {
	var isk ISK

	isk.X = FP256BN.FromBytes(encoded.X)
	isk.Y = FP256BN.FromBytes(encoded.Y)

	return &isk
}

type MiddleEncodedIPK struct {
	X  []byte
	Y  []byte
	C  []byte
	SX []byte
	SY []byte
}

func (ipk *IPK) Encode() *MiddleEncodedIPK {
	var encoded MiddleEncodedIPK

	encoded.X = ecp2ToBytes(ipk.X)
	encoded.Y = ecp2ToBytes(ipk.Y)
	encoded.C = bigToBytes(ipk.C)
	encoded.SX = bigToBytes(ipk.SX)
	encoded.SY = bigToBytes(ipk.SY)

	return &encoded
}

func (encoded *MiddleEncodedIPK) Decode() *IPK {
	var decoded IPK

	decoded.X = FP256BN.ECP2_fromBytes(encoded.X)
	decoded.Y = FP256BN.ECP2_fromBytes(encoded.Y)
	decoded.C = FP256BN.FromBytes(encoded.C)
	decoded.SX = FP256BN.FromBytes(encoded.SX)
	decoded.SY = FP256BN.FromBytes(encoded.SY)

	return &decoded
}

type MiddleEncodedCredential struct {
	A []byte
	B []byte
	C []byte
	D []byte
}

func (cred *Credential) Encode() *MiddleEncodedCredential {
	var encoded MiddleEncodedCredential

	encoded.A = ecpToBytes(cred.A)
	encoded.B = ecpToBytes(cred.B)
	encoded.C = ecpToBytes(cred.C)
	encoded.D = ecpToBytes(cred.D)

	return &encoded
}

func (encoded *MiddleEncodedCredential) Decode() *Credential {
	var decoded Credential

	decoded.A = FP256BN.ECP_fromBytes(encoded.A)
	decoded.B = FP256BN.ECP_fromBytes(encoded.B)
	decoded.C = FP256BN.ECP_fromBytes(encoded.C)
	decoded.D = FP256BN.ECP_fromBytes(encoded.D)

	return &decoded
}

type MiddleEncodedProof struct {
	SmallC []byte
	SmallN []byte
	SmallS []byte
	K      []byte
}

func (proof *SchnorrProof) Encode() *MiddleEncodedProof {

	var encoded MiddleEncodedProof
	encoded.SmallC = bigToBytes(proof.SmallC)
	encoded.SmallN = bigToBytes(proof.SmallN)
	encoded.SmallS = bigToBytes(proof.SmallS)
	encoded.K = ecpToBytes(proof.K)

	return &encoded
}

func (proof *MiddleEncodedProof) Decode() *SchnorrProof {
	var decoded SchnorrProof

	decoded.SmallC = FP256BN.FromBytes(proof.SmallC)
	decoded.SmallS = FP256BN.FromBytes(proof.SmallS)
	decoded.SmallN = FP256BN.FromBytes(proof.SmallN)
	decoded.K = FP256BN.ECP_fromBytes(proof.K)

	return &decoded
}

type MiddleEncodedSignature struct {
	Credential *MiddleEncodedCredential
	Proof      *MiddleEncodedProof
}

func (signature *Signature) Encode() *MiddleEncodedSignature {
	var encoded MiddleEncodedSignature
	encoded.Credential = signature.RandomizedCred.Encode()
	encoded.Proof = signature.Proof.Encode()

	return &encoded
}

func (encoded *MiddleEncodedSignature) Decode() *Signature {
	var decoded Signature

	decoded.RandomizedCred = encoded.Credential.Decode()
	decoded.Proof = encoded.Proof.Decode()

	return &decoded
}

type MiddleEncodedJoinSeed struct {
	Basename []byte
	S2       []byte
	Y2       []byte
}

func (seeds *JoinSeed) Encode() *MiddleEncodedJoinSeed {
	var encoded MiddleEncodedJoinSeed
	encoded.Basename = seeds.Basename
	encoded.S2 = seeds.S2
	encoded.Y2 = bigToBytes(seeds.Y2)

	return &encoded
}

func (encoded *MiddleEncodedJoinSeed) Decode() *JoinSeed {
	var decoded JoinSeed
	decoded.Basename = encoded.Basename
	decoded.S2 = encoded.S2
	decoded.Y2 = FP256BN.FromBytes(encoded.Y2)

	return &decoded
}

type MiddleEncodedJoinRequest struct {
	Proof *MiddleEncodedProof
	Q     []byte
}

func (request *JoinRequest) Encode() *MiddleEncodedJoinRequest {
	var encoded MiddleEncodedJoinRequest

	encoded.Q = ecpToBytes(request.Q)
	encoded.Proof = request.Proof.Encode()

	return &encoded
}

func (encoded *MiddleEncodedJoinRequest) Decode() *JoinRequest {
	var decoded JoinRequest

	decoded.Q = FP256BN.ECP_fromBytes(encoded.Q)
	decoded.Proof = encoded.Proof.Decode()

	return &decoded
}

type MiddleEncodedJoinRequestTPM struct {
	JoinReq *MiddleEncodedJoinRequest
	EKCert  []byte
	SrkName []byte
}

func (request *JoinRequestTPM) Encode() *MiddleEncodedJoinRequestTPM {
	var encoded MiddleEncodedJoinRequestTPM
	encoded.EKCert = request.EKCert.Raw
	encoded.SrkName = request.SrkName

	encoded.JoinReq = request.JoinReq.Encode()
	return &encoded
}

func (encoded *MiddleEncodedJoinRequestTPM) Decode() (*JoinRequestTPM, error) {
	var err error
	var decoded JoinRequestTPM

	decoded.JoinReq = encoded.JoinReq.Decode()

	decoded.SrkName = encoded.SrkName
	decoded.EKCert, err = x509.ParseCertificate(encoded.EKCert)

	if err != nil {
		return nil, err
	}

	return &decoded, nil
}

type MiddleEncodedCredCipher struct {
	WrappedCredential []byte
	IdObject          []byte
	EncA              []byte
	EncC              []byte
	IV                []byte
}

func (cipher *CredentialCipher) Encode() *MiddleEncodedCredCipher {
	var encoded MiddleEncodedCredCipher

	encoded.WrappedCredential = cipher.WrappedCredential
	encoded.IdObject = cipher.IdObject

	encoded.EncA = cipher.EncA
	encoded.EncC = cipher.EncC

	encoded.IV = cipher.IV

	return &encoded
}

func (encoded *MiddleEncodedCredCipher) Decode() *CredentialCipher {
	var decoded CredentialCipher

	decoded.WrappedCredential = encoded.WrappedCredential
	decoded.IdObject = encoded.IdObject

	decoded.EncA = encoded.EncA
	decoded.EncC = encoded.EncC

	decoded.IV = encoded.IV

	return &decoded
}

func EncodeRevocationList(list RevocationList) [][]byte {
	var result [][]byte

	for _, sk := range list {
		encoded := bigToBytes(sk)
		result = append(result, encoded)
	}

	return result
}

func DecodeRevocationList(list [][]byte) RevocationList {
	result := RevocationList{}

	for _, sk := range list {
		decoded := FP256BN.FromBytes(sk)
		result = append(result, decoded)
	}

	return result
}
