# ecdaa

A library of ECDAA with TPM (Trusted Platform Module).

ECDAA is a privacy-enhancing cryptographic primitive.
ECDAA prevents tracking but attests that the computer is in some group.

The central use-case of ECDAA is proving the manufacturer of computers for security reasons (e.g. prove how secret keys are stored) but the end-user is concerned about tracking.

This library mainly supports the [FIDO ECDAA](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-ecdaa-algorithm-v2.0-id-20180227.html), but it uses `TPM2_Sign` instead of `TPM2_Certify` for extensibility.

## Installation

```sh
git clone https://github.com/akakou/ecdaa
cd ./ecdaa/thirdparty
sh ./install.sh
```

## Test

**WARNING: All keys in TPM are deleted.**

```
sudo tpm2_clear && sudo go test --run TestAll
```

