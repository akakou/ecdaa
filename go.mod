module github.com/akakou/ecdaa

go 1.21.4

require (
	github.com/akakou/mcl_utils v0.0.0
	github.com/google/go-tpm v0.3.3
)

require golang.org/x/sys v0.0.0-20210629170331-7dc0b73dc9fb // indirect

require (
	github.com/akakou-fork/amcl-go/miracl v0.0.0-20240206092846-d00185b82d38 // indirect
	github.com/google/go-cmp v0.5.5 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)

replace github.com/akakou/mcl_utils => ./mcl_utils

replace github.com/google/go-tpm => ./thirdparty/go-tpm
