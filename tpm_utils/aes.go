package tpm_utils

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"miracl/core/FP256BN"
)

func EncCredAES(srcA, srcC, secret, iv []byte) ([]byte, []byte, error) {
	var destA, destC [FP256BN.MODBYTES + 1]byte

	secretCipher, err := aes.NewCipher(secret)

	if err != nil {
		return nil, nil, fmt.Errorf("%v", err)
	}

	secretCFBEncrypter := cipher.NewCFBEncrypter(secretCipher, iv)
	secretCFBEncrypter.XORKeyStream(destA[:], srcA[:])

	secretCFBEncrypter = cipher.NewCFBEncrypter(secretCipher, iv)
	secretCFBEncrypter.XORKeyStream(destC[:], srcC[:])

	return destA[:], destC[:], nil
}

func DecCredAES(srcA, srcC, secret, iv []byte) ([]byte, []byte, error) {
	var destA, destC [FP256BN.MODBYTES + 1]byte

	secretCipher, err := aes.NewCipher(secret)

	if err != nil {
		return nil, nil, fmt.Errorf("%v", err)
	}

	secretCFBDecrypter := cipher.NewCFBDecrypter(secretCipher, iv)
	secretCFBDecrypter.XORKeyStream(destA[:], srcA[:])

	secretCFBDecrypter = cipher.NewCFBDecrypter(secretCipher, iv)
	secretCFBDecrypter.XORKeyStream(destC[:], srcC[:])

	return destA[:], destC[:], nil
}
