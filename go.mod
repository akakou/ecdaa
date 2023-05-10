module github.com/akakou/ecdaa

go 1.18

require (
	github.com/google/go-tpm v0.3.3
	golang.org/x/sys v0.0.0-20210629170331-7dc0b73dc9fb
	miracl v0.0.0
)

require (
	github.com/google/go-cmp v0.5.5 // indirect
	github.com/google/go-tpm-tools v0.2.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)

replace miracl => ./thirdparty/miracl

replace github.com/google/go-tpm => ./thirdparty/go-tpm
