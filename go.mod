module example.com/m/v2

go 1.18

require miracl v0.0.0

require go-tpm v0.0.0

require (
	github.com/google/go-tpm v0.3.0 // indirect
	golang.org/x/sys v0.0.0-20210629170331-7dc0b73dc9fb // indirect
)

replace miracl => ./thirdparty/miracl

replace go-tpm => ./thirdparty/go-tpm
