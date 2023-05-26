BITS = 64
CONFIG_PY = config${BITS}.py

all: ./go-tpm ./miracl ./core
	echo "Done"

./go-tpm:
	git clone https://github.com/akakou/go-tpm \
	&& cd go-tpm && git checkout ecdaa

./miracl: ./core
	mkdir miracl \
	&& cd miracl \
	&& go mod init miracl \
	&& cp -r ../core/go/* . 

./core:
	git clone https://github.com/miracl/core/  \
	&& cd core/go \
	&& echo -e "32\n0\n" | python3 ${CONFIG_PY}
 
clean:
	rm -rf ./go-tpm ./miracl ./core
