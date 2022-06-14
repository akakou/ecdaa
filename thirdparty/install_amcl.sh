git clone https://github.com/miracl/core/

mkdir miracl
cd miracl
go mod init miracl

cp -r ../core/go/* .

cd core/go
echo -e "32\n\n" | python3 config64.py
