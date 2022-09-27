package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	labelIdentity  = "IDENTITY"
	labelStorage   = "STORAGE"
	labelIntegrity = "INTEGRITY"
)

/**
 * this function is copied from go-tpm/legacy/tpm2/credactivation/credactivation.go
 */
func MakeCred(aik *legacy.HashValue, pub crypto.PublicKey, symBlockSize int, secret []byte) ([]byte, []byte, error) {
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("only RSA public keys are supported for credential activation")
	}

	crypothash, err := aik.Alg.Hash()
	if err != nil {
		return nil, nil, err
	}

	// The seed length should match the keysize used by the EKs symmetric cipher.
	// For typical RSA EKs, this will be 128 bits (16 bytes).
	// Spec: TCG 2.0 EK Credential Profile revision 14, section 2.1.5.1.
	seed := make([]byte, symBlockSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, nil, fmt.Errorf("generating seed: %v", err)
	}

	// Encrypt the seed value using the provided public key.
	// See annex B, section 10.4 of the TPM specification revision 2 part 1.
	label := append([]byte(labelIdentity), 0)
	encSecret, err := rsa.EncryptOAEP(crypothash.New(), rand.Reader, rsaPub, seed, label)
	if err != nil {
		return nil, nil, fmt.Errorf("generating encrypted seed: %v", err)
	}

	// Generate the encrypted credential by convolving the seed with the digest of
	// the AIK, and using the result as the key to encrypt the secret.
	// See section 24.4 of TPM 2.0 specification, part 1.
	aikNameEncoded := aik.Value
	// aikNameEncoded, err := aik.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("encoding aikName: %v", err)
	}
	h, err := aik.Alg.Hash()
	if err != nil {
		return nil, nil, fmt.Errorf("generating symmetric key: %v", err)
	}
	symmetricKey := legacy.KDFaHash(h, seed, labelStorage, aikNameEncoded, nil, len(seed)*8)
	c, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, nil, fmt.Errorf("symmetric cipher setup: %v", err)
	}
	cv, err := tpmutil.Pack(tpmutil.U16Bytes(secret))
	if err != nil {
		return nil, nil, fmt.Errorf("generating cv (TPM2B_Digest): %v", err)
	}

	// IV is all null bytes. encIdentity represents the encrypted credential.
	encIdentity := make([]byte, len(cv))
	cipher.NewCFBEncrypter(c, make([]byte, len(symmetricKey))).XORKeyStream(encIdentity, cv)

	// Generate the integrity HMAC, which is used to protect the integrity of the
	// encrypted structure.
	// See section 24.5 of the TPM specification revision 2 part 1.
	macKey := legacy.KDFaHash(h, seed, labelIntegrity, nil, nil, crypothash.Size()*8)

	mac := hmac.New(crypothash.New, macKey)
	mac.Write(encIdentity)
	mac.Write(aikNameEncoded)
	integrityHMAC := mac.Sum(nil)

	idObject := &legacy.IDObject{
		IntegrityHMAC: integrityHMAC,
		EncIdentity:   encIdentity,
	}
	id, err := tpmutil.Pack(idObject)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding IDObject: %v", err)
	}

	packedID, err := tpmutil.Pack(tpmutil.U16Bytes(id))
	if err != nil {
		return nil, nil, fmt.Errorf("packing id: %v", err)
	}
	packedEncSecret, err := tpmutil.Pack(tpmutil.U16Bytes(encSecret))
	if err != nil {
		return nil, nil, fmt.Errorf("packing encSecret: %v", err)
	}

	return packedID, packedEncSecret, nil
}
