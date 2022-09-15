### step1. install go-tpm
git clone https://github.com/akakou/go-tpm
cd go-tpm
git checkout fix-create-ecdaa-key
cd ..

### step2. install miracl/core

git clone https://github.com/miracl/core/

mkdir miracl
cd miracl
go mod init miracl

cp -r ../core/go/* .

cd core/go
echo -e "32\n\n" | python3 config64.py
