package ecdaa

import (
	"bytes"
	"crypto/x509"
	"encoding/gob"
	"fmt"
	"mcl_utils"
	"miracl/core/FP256BN"
)

func Encode[T any](data T) ([]byte, error) {
	var network bytes.Buffer
	enc := gob.NewEncoder(&network)

	err := enc.Encode(data)
	return network.Bytes(), err
}

func Decode[T any](target T, buf []byte) error {
	var network bytes.Buffer
	network.Write(buf)

	dec := gob.NewDecoder(&network)
	err := dec.Decode(&target)

	return err
}

type MiddleEncodedISK struct {
	X []byte
	Y []byte
}

func (isk *ISK) Encode() ([]byte, error) {
	var mid MiddleEncodedISK

	mid.X = mcl_utils.BigToBytes(isk.X)
	mid.Y = mcl_utils.BigToBytes(isk.Y)

	return Encode(&mid)
}

func (isk *ISK) Decode(encoded []byte) error {
	var mid MiddleEncodedISK

	err := Decode(&mid, encoded)

	if err != nil {
		return err
	}

	isk.X = FP256BN.FromBytes(mid.X)
	isk.Y = FP256BN.FromBytes(mid.Y)

	return nil
}

type MiddleEncodedIPK struct {
	X  []byte
	Y  []byte
	C  []byte
	SX []byte
	SY []byte
}

func (ipk *IPK) Encode() ([]byte, error) {
	var mid MiddleEncodedIPK

	mid.X = mcl_utils.Ecp2ToBytes(ipk.X)
	mid.Y = mcl_utils.Ecp2ToBytes(ipk.Y)
	mid.C = mcl_utils.BigToBytes(ipk.C)
	mid.SX = mcl_utils.BigToBytes(ipk.SX)
	mid.SY = mcl_utils.BigToBytes(ipk.SY)

	return Encode(mid)
}

func (decoded *IPK) Decode(encoded []byte) error {
	var mid MiddleEncodedIPK

	err := Decode(&mid, encoded)
	if err != nil {
		fmt.Printf("error")
		return err
	}

	decoded.X = FP256BN.ECP2_fromBytes(mid.X)
	decoded.Y = FP256BN.ECP2_fromBytes(mid.Y)
	decoded.C = FP256BN.FromBytes(mid.C)
	decoded.SX = FP256BN.FromBytes(mid.SX)
	decoded.SY = FP256BN.FromBytes(mid.SY)

	return nil
}

type MiddleEncodedCredential struct {
	A []byte
	B []byte
	C []byte
	D []byte
}

func (cred *Credential) Encode() ([]byte, error) {
	var mid MiddleEncodedCredential

	mid.A = mcl_utils.EcpToBytes(cred.A)
	mid.B = mcl_utils.EcpToBytes(cred.B)
	mid.C = mcl_utils.EcpToBytes(cred.C)
	mid.D = mcl_utils.EcpToBytes(cred.D)

	return Encode(mid)
}

func (decoded *Credential) Decode(encoded []byte) error {
	var mid MiddleEncodedCredential

	err := Decode(&mid, encoded)
	if err != nil {
		return err
	}

	decoded.A = FP256BN.ECP_fromBytes(mid.A)
	decoded.B = FP256BN.ECP_fromBytes(mid.B)
	decoded.C = FP256BN.ECP_fromBytes(mid.C)
	decoded.D = FP256BN.ECP_fromBytes(mid.D)

	return nil
}

type MiddleEncodedProof struct {
	SmallC []byte
	SmallN []byte
	SmallS []byte
	K      []byte
}

func (proof *SchnorrProof) Encode() ([]byte, error) {
	var mid MiddleEncodedProof

	mid.SmallC = mcl_utils.BigToBytes(proof.SmallC)
	mid.SmallN = mcl_utils.BigToBytes(proof.SmallN)
	mid.SmallS = mcl_utils.BigToBytes(proof.SmallS)
	mid.K = mcl_utils.EcpToBytes(proof.K)

	return Encode(mid)
}

func (decoded *SchnorrProof) Decode(encoded []byte) error {
	var mid MiddleEncodedProof

	err := Decode(&mid, encoded)
	if err != nil {
		return nil
	}

	decoded.SmallC = FP256BN.FromBytes(mid.SmallC)
	decoded.SmallS = FP256BN.FromBytes(mid.SmallS)
	decoded.SmallN = FP256BN.FromBytes(mid.SmallN)
	decoded.K = FP256BN.ECP_fromBytes(mid.K)

	return nil
}

type MiddleEncodedSignature struct {
	Credential []byte
	Proof      []byte
}

func (signature *Signature) Encode() ([]byte, error) {
	var err error
	var mid MiddleEncodedSignature

	mid.Credential, err = signature.RandomizedCred.Encode()

	if err != nil {
		return nil, err
	}

	mid.Proof, err = signature.Proof.Encode()

	if err != nil {
		return nil, err
	}

	return Encode(mid)
}

func (decoded *Signature) Decode(encoded []byte) error {
	var mid MiddleEncodedSignature
	var cred Credential
	var proof SchnorrProof

	err := Decode(&mid, encoded)
	if err != nil {
		return err
	}

	err = cred.Decode(mid.Credential)

	if err != nil {
		return err
	}

	err = proof.Decode(mid.Proof)

	if err != nil {
		return err
	}

	decoded.RandomizedCred = &cred
	decoded.Proof = &proof

	return nil
}

type MiddleEncodedJoinSeed struct {
	Basename []byte
	S2       []byte
	Y2       []byte
}

func (seeds *JoinSeed) Encode() ([]byte, error) {
	var mid MiddleEncodedJoinSeed
	mid.Basename = seeds.Basename
	mid.S2 = seeds.S2
	mid.Y2 = mcl_utils.BigToBytes(seeds.Y2)

	return Encode(mid)
}

func (decoded *JoinSeed) Decode(encoded []byte) error {
	var mid MiddleEncodedJoinSeed

	err := Decode(&mid, encoded)

	if err != nil {
		return err
	}

	decoded.Basename = mid.Basename
	decoded.S2 = mid.S2
	decoded.Y2 = FP256BN.FromBytes(mid.Y2)

	return nil
}

type MiddleEncodedJoinRequest struct {
	Proof []byte
	Q     []byte
}

func (request *JoinRequest) Encode() ([]byte, error) {
	var err error
	var mid MiddleEncodedJoinRequest

	mid.Q = mcl_utils.EcpToBytes(request.Q)
	mid.Proof, err = request.Proof.Encode()

	if err != nil {
		return nil, err
	}

	return Encode(mid)
}

func (decoded *JoinRequest) Decode(encoded []byte) error {
	var mid MiddleEncodedJoinRequest

	err := Decode(&mid, encoded)

	if err != nil {
		return nil
	}

	decoded.Q = FP256BN.ECP_fromBytes(mid.Q)

	decoded.Proof = &SchnorrProof{}
	err = decoded.Proof.Decode(mid.Proof)

	return err
}

type MiddleEncodedJoinRequestTPM struct {
	JoinReq []byte
	EKCert  []byte
	SrkName []byte
}

func (request *JoinRequestTPM) Encode() ([]byte, error) {
	var mid MiddleEncodedJoinRequestTPM
	var err error

	mid.EKCert = request.EKCert.Raw
	mid.SrkName = request.SrkName
	mid.JoinReq, err = request.JoinReq.Encode()

	if err != nil {
		return nil, err
	}

	return Encode(mid)
}

func (decoded *JoinRequestTPM) Decode(encoded []byte) error {
	var mid MiddleEncodedJoinRequestTPM
	decoded.JoinReq = &JoinRequest{}

	err := Decode(&mid, encoded)

	if err != nil {
		fmt.Printf("1. %v", err)

		return err
	}

	decoded.SrkName = mid.SrkName
	decoded.EKCert, err = x509.ParseCertificate(mid.EKCert)

	if err != nil {
		fmt.Printf("2. %v", err)

		return err
	}

	err = decoded.JoinReq.Decode(mid.JoinReq)

	if err != nil {
		fmt.Printf("3. %v", err)

		return err
	}

	return nil

}

type MiddleEncodedCredCipher struct {
	WrappedCredential []byte
	IdObject          []byte
	EncA              []byte
	EncC              []byte
	IV                []byte
}

func (cipher *CredentialCipher) Encode() ([]byte, error) {
	return Encode(cipher)
}

func (decoded *CredentialCipher) Decode(buf []byte) error {
	return Decode(decoded, buf)
}

func EncodeRevocationList(list RevocationList) [][]byte {
	var result [][]byte

	for _, sk := range list {
		encoded := mcl_utils.BigToBytes(sk)
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
