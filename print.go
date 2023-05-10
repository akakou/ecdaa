package ecdaa

import (
	"fmt"
	"miracl/core/FP256BN"
)

func printECP(ecp *FP256BN.ECP) {
	fmt.Printf("=== %v ===\n", ecp)
	fmt.Printf("x = %v\n", ecp.GetX().ToString())
	fmt.Printf("y = %v\n", ecp.GetY().ToString())
}
