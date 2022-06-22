module example.com/m/v2

go 1.18

require miracl v0.0.0

require go-tpm v0.0.0

require (
	github.com/google/certificate-transparency-go v1.1.2 // indirect
	github.com/google/go-attestation v0.4.4-0.20220404204839-8820d49b18d9 // indirect
	github.com/google/go-tpm v0.3.3 // indirect
	github.com/google/go-tpm-tools v0.3.8 // indirect
	github.com/google/go-tspi v0.2.1-0.20190423175329-115dea689aad // indirect
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5 // indirect
	golang.org/x/sys v0.0.0-20220209214540-3681064d5158 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
)

replace miracl => ./thirdparty/miracl

replace go-tpm => ./thirdparty/go-tpm
