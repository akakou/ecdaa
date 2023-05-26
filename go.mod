module github.com/akakou/ecdaa

go 1.18

require (
	github.com/google/go-tpm v0.3.3
	golang.org/x/sys v0.0.0-20220722155257-8c9f86f7a55f
	miracl v0.0.0
)

require (
	github.com/google/go-cmp v0.5.5 // indirect
	github.com/google/go-tpm-tools v0.2.0 // indirect
	golang.org/x/exp v0.0.0-20190731235908-ec7cb31e5a56 // indirect
	golang.org/x/image v0.0.0-20190802002840-cff245a6509b // indirect
	golang.org/x/mobile v0.0.0-20230427221453-e8d11dd0ba41 // indirect
	golang.org/x/mod v0.6.0-dev.0.20220419223038-86c51ed26bb4 // indirect
	golang.org/x/tools v0.1.12 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)

replace miracl => ./thirdparty/miracl

replace github.com/google/go-tpm => ./thirdparty/go-tpm
