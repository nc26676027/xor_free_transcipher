# Code for paper : "XBOOT: Free-XOR Gates for CKKS  with Applications to Transciphering"

This code is built upon the Open-sourced FHE library Lattigo V6.0.

# XBOOT transciphering

We implement the hybrid framework in [./BtR_framework/ckks_cipher/](./BtR_framework/ckks_cipher/), which contains the following functionalities.
- Evaluation of the AES-CTR in the CKKS scheme

We implement the ResNet-20 cnn_infer in [./BtR_framework/cnn_infer/](./BtR_framework/cnn_infer/), which contains the following functionalities.
- ResNet20 inference scheme (located at (./cnn_infer))

We implement the GAWS chisqtest in [./BtR_framework/chisqtest/](./BtR_framework/chisqtest/), which contains the following functionalities.
- chisq test scheme (located at (./chisq.go))

An example of Running ResNet20 inference in the BtR framework is given in [examples/resnet](./BtR_framework/examples/resnet/main.go).

An example of Running GWAS chisqtest in the BtR framework is given in [BtR_framework/chisqtest/](./BtR_framework/chisqtest/chisq.go).

## Run transciphering experiment

cd into corresponding dir
```PowerShell
cd ./examples/transcipher/main.go
go run main.go
```

