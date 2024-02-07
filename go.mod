module github.com/akakou/ecdaa

go 1.21.4

require (
	github.com/akakou-fork/amcl-go/miracl v0.0.0-20240206094909-344c847a50cc
	github.com/akakou/fp256bn-amcl-utils v0.0.2
	github.com/google/go-tpm v0.9.1-0.20240206213016-638c2b803c16
)

require golang.org/x/sys v0.16.0 // indirect

// replace github.com/google/go-tpm => ../tmp/go-tpm
