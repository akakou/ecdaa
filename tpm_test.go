package main

import (
	"fmt"
	"testing"
)

// func printPublic(p tpm2.TPM2BPublic, name string) {
// 	fmt.Printf("----- %v ----\n", name)

// 	inPublic, err := p.PublicArea.Unique.ECC.
// 	if err != nil {
// 		log.Fatalf("error")
// 	}

// 	for _, v := range inPublic {
// 		fmt.Printf("%02x ", v)
// 	}

// 	fmt.Printf("\n----- ----- ----\n\n")
// }

func TestCreateKey(t *testing.T) {
	handle, ekP, keyP, err := CreateKey()

	if err != nil {
		t.Errorf("%v", err)
	}

	fmt.Printf("handle: %v\n", handle)
	fmt.Printf("ek public key: %v\n", ekP)
	fmt.Printf("key public key: %v\n", keyP)
}

func TestReadEKCert(t *testing.T) {
	cert, err := ReadEKCert()

	if err != nil {
		t.Errorf("%v", err)
	}

	fmt.Printf("%v\n", cert.PublicKeyAlgorithm)
}

// func TestNameMatchesPublicArea(t *testing.T) {
// 	rwc, err := tpm2.OpenTPM("/dev/tpm0")
// 	defer client.CheckedClose(t, rwc)

// 	ek, err := client.EndorsementKeyRSA(rwc)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	defer ek.Close()

// 	matches, err := ek.Name().MatchesPublic(ek.PublicArea())
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	if !matches {
// 		t.Fatal("Returned name and computed name do not match")
// 	}
// }
