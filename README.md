# Code for paper : "XBOOT: Free-XOR Gates for CKKS  with Applications to Transciphering"

This code is built upon the Open-sourced FHE library Lattigo v6.0 https://github.com/tuneinsight/lattigo

go version go1.22.5 linux/amd64 tested
# XBOOT transciphering

We implement the XBOOT transcipering in [./ckks_cipher/](./ckks_cipher/), which contains the following functionalities.
- Evaluation of the AES-CTR in the CKKS scheme
- Evaluation of the Rasta-CTR in the CKKS scheme

We implement the GAWS chisqtest in [./chisqtest/](./chisqtest/), which contains the following functionalities.
- chisq test scheme (located at (./chisq.go))

An example of Running GWAS chisqtest subsequent XBOOT transciphering is given in [./examples/chisq/main.go](./examples/chisq/main.go).

An example of Running XBOOT-AES transciphering is given in [./examples/transcipher/main.go](./examples/transcipher/main.go).

## Run transciphering experiment

cd into corresponding dir
```PowerShell
cd ./examples/transcipher/main.go
go run main.go
```

