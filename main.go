package main

import "fmt"

func main() {
	rng := InitRandom()

	isk := RandomISK(rng)
	ipk := RandomIPK(&isk, rng)

	err := VerifyIPK(&ipk)
	fmt.Printf("err: %v", err)
}
