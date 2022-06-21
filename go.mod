module example.com/m/v2

go 1.18

require miracl v0.0.0

require go-tpm v0.0.0

require (
	github.com/google/go-tpm v0.3.3 // indirect
	github.com/google/go-tpm-tools v0.3.8 // indirect
	golang.org/x/sys v0.0.0-20220209214540-3681064d5158 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
)

replace miracl => ./thirdparty/miracl

replace go-tpm => ./thirdparty/go-tpm
