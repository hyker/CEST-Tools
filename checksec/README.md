# Checksec tool enclave
A simple tool to verify the security properties of your binaries.

Link to original repo: https://github.com/Wenzel/checksec.py

## Changes
The CEST-version has some minor changes from the original program to make it perform better in an enclave enviroment. It was made to run on a single thread and there was changes to how ldconfig is found on the system. 

For more details on these changes see the repo of the fork that is running in the enclave: https://github.com/hyker/checksec.py

## MRENCLAVE
To verify that the software running inside the enclave is the same as in this repo, you can compare the MRENCALVE value. The MRENCLAVE value uniquely identifies an enclave and will change if any software is modified. The MRENCLAVE value will be printed during the docker build process and can be accessed from within the enclave the while in the root folder with the command:
```console
gramine-sgx-get-token --output python3.token --sig python3.sig | grep mr_enclave
```
The lastest MRENCLAVE value for Checksec tool enclave was (base64): 
```
ZylwUX/esNFxBjDZmrkujhFu8LDJn+PjBF2AN3RR4jc=
```
