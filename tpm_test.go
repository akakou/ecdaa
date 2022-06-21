package main

import (
	"fmt"
	"go-tpm/tpm2"
	"log"
	"testing"
)

func printPublic(p tpm2.Public, name string) {
	fmt.Printf("----- %v ----\n", name)

	inPublic, err := p.Encode()
	if err != nil {
		log.Fatalf("error")
	}

	for _, v := range inPublic {
		fmt.Printf("%02x ", v)
	}

	fmt.Printf("\n----- ----- ----\n\n")
}

func TestTPM(t *testing.T) {
	key, err := CreateKey()

	if err != nil {
		t.Errorf("%v", err)
	}

	fmt.Printf("%v\n", key)
}
