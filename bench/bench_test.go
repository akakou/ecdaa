package ecdaa_bench

import (
	"testing"
)

func checkError(err error, t *testing.B) {
	if err != nil {
		t.Fatalf("%v", err)
	}
}
