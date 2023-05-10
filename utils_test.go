package ecdaa

import (
	"reflect"
	"testing"
)

func TestEncDecCred(t *testing.T) {
	msg := []byte("0123456789abcdef0123456789abcdef!")
	secret := []byte("0123456789abcdef")
	iv := []byte("0123456789abcdef")

	encA, encC, err := encCredAES(msg, msg, secret, iv)
	if err != nil {
		t.Fatalf("%v", err)
	}

	decA, decC, err := decCredAES(encA, encC, secret, iv)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !reflect.DeepEqual(decA, msg) {
		t.Fatalf("not match: %v != %v", decA, msg)
	}

	if !reflect.DeepEqual(decC, msg) {
		t.Fatalf("not match: %v != %v", decC, msg)
	}
}
