package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"miracl/core/FP256BN"
)

func encCredAES(srcA, srcC, secret []byte) ([]byte, []byte, error) {
	var destA, destC [FP256BN.MODBYTES + 1]byte

	iv := []byte("0123456789abcdef")

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

func decCredAES(srcA, srcC, secret []byte) ([]byte, []byte, error) {
	var destA, destC [FP256BN.MODBYTES + 1]byte

	iv := []byte("0123456789abcdef")

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
