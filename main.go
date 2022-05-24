package main

import (
	"io/ioutil"
	"log"

	"github.com/google/go-attestation/attest"
)

var tpm *attest.TPM

func main() {
	err := initTPM()

	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	ek, param, err := reqRegisration()

	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	ec, err := makeCred(*ek, *param)

	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	err = acivateCred(ec)

	if err != nil {
		log.Fatalf("Error: %v", err)
	} else {
		println("ok!")
	}
}

func initTPM() error {
	config := &attest.OpenConfig{}

	tmpTpm, err := attest.OpenTPM(config)
	if err != nil {

		return err
	}

	tpm = tmpTpm

	return nil
}

func reqRegisration() (*attest.EK, *attest.AttestationParameters, error) {
	eks, err := tpm.EKs()
	if err != nil {

	}
	ek := eks[0]

	akConfig := &attest.AKConfig{}
	ak, err := tpm.NewAK(akConfig)
	if err != nil {

		return nil, nil, err
	}
	attestParams := ak.AttestationParameters()

	akBytes, err := ak.Marshal()
	if err != nil {

		return nil, nil, err
	}

	if err := ioutil.WriteFile("encrypted_aik.json", akBytes, 0600); err != nil {

		return nil, nil, err
	}

	return &ek, &attestParams, nil
}

func makeCred(ek attest.EK, attestParams attest.AttestationParameters) (*attest.EncryptedCredential, error) {
	params := attest.ActivationParameters{
		TPMVersion: 2,
		EK:         ek.Public,
		AK:         attestParams,
	}
	_, encryptedCredentials, err := params.Generate()
	if err != nil {

		return nil, err
	}

	return encryptedCredentials, err
}

func acivateCred(encryptedCredentials *attest.EncryptedCredential) error {
	akBytes, err := ioutil.ReadFile("encrypted_aik.json")
	if err != nil {

		return err
	}
	ak, err := tpm.LoadAK(akBytes)
	if err != nil {

		return err
	}
	_, err = ak.ActivateCredential(tpm, *encryptedCredentials)
	if err != nil {
		return err
	}

	return nil
}
