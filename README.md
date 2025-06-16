# XBOOT: Free-XOR Gates for CKKS  with Applications to Transciphering
This is the code for our work in CHES 2025, named ***[XBOOT: Free-XOR Gates for CKKS  with Applications to Transciphering](https://eprint.iacr.org/2025/074)***.
Our implementation is based on the Open-sourced FHE library [Lattigo v6.0](https://github.com/tuneinsight/lattigo) [1]. 

## Golang installation and configuration
Downloading the latest version of go binary distribution:
```PowerShell
wget https://go.dev/dl/go1.24.4.linux-amd64.tar.gz
```
Delete the existing Golang, and unzip the downloaded file into the environment:
```PowerShell
sudo rm -rf /usr/local/go        # delete old version if exists
sudo tar -C /usr/local -xzf go1.24.4.linux-amd64.tar.gz
```
Editing the shell file and adding the following command (if not existing):
```PowerShell
nano ~/.bashrc
export PATH=$PATH:/usr/local/go/bin
```
Saving and enabling:
```PowerShell
source ~/.bashrc
```
## General information about the code structure
### XBOOT bootstrapping scheme
This part is located at 
```
# Modified EvalMod function
./circuits/ckks/mod1
# New bootstrapping function added
./circuits/ckks/bootstrapping
# The EvalMod f_bin interpolation function
./utils/cosine/cosine_approx.go
```
### XBOOT based transciphering scheme

We implement the XBOOT transcipering in [./ckks_cipher/](./ckks_cipher/), which contains the following functionalities.
- Evaluation of the AES-CTR in the CKKS scheme
- Evaluation of the Rasta-CTR in the CKKS scheme

### Application subsequent transciphering
We implement the GAWS chisqtest in [./chisqtest/](./chisqtest/), which contains the following functionalities.
- chisq test scheme (located at (./chisq.go))

### Example containing
An example of Running GWAS chisqtest subsequent XBOOT transciphering is given in [./examples/chisq/main.go](./examples/chisq/main.go).

An example of Running XBOOT-AES transciphering is given in [./examples/transcipher/main.go](./examples/transcipher/main.go).


## Compile and Run XBOOT
A proof of concept unsecure toy case for AES-CKKS transciphering 
```PowerShell
cd ./examples/transcipher/main.go
go run main.go --mode=test
```

## Benchmark the AES-CKKS transiphering 
Ensure you have sufficient RAM (approximately 64GB) and 64 physical CPU cores for improved parallelization. 

```PowerShell
cd ./examples/transcipher/main.go
go run main.go --mode=benchmark
```

## Paper
For a detailed description of the framework, please refer to our paper:

Chao Niu, Zhicong Huang, Zhaomin Yang, Yi Chen, Liang Kong, Cheng Hong and Tai Wei. 2025. **XBOOT: Free-XOR Gates for CKKS with
Applications to Transciphering** IACR Transactions on Cryptographic Hardware and Embedded Systems, 2025(4), xx-xx. \[[Link](TODO)\] \[[DOI](TODO)\]

## References
[1] "Lattigo v6" Online: https://github.com/tuneinsight/lattigo Aug, 2024.

## Disclaimer
The client-side symmetric encryption function and the FHE key schedule evaluation are not currently included.

## License
Lattigo is licensed under the Apache 2.0 License. See [LICENSE](https://github.com/tuneinsight/lattigo/blob/master/LICENSE).

