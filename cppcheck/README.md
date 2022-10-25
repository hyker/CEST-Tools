# Cppcheck tool enclave
Cppcheck is a static analysis tool for C/C++ code. It provides unique code analysis to detect bugs and focuses on detecting undefined behaviour and dangerous coding constructs. The goal is to have very few false positives. Cppcheck is designed to be able to analyze your C/C++ code even if it has non-standard syntax (common in embedded projects).

Link to original repo: https://github.com/danmar/cppcheck

## Changes
The CEST-platform run an unmodified version of Cppcheck.

## MRENCLAVE
To verify that the software running inside the enclave is the same as in this repo, you can compare the MRENCALVE value. The MRENCLAVE value uniquely identifies an enclave and will change if any software is modified. The MRENCLAVE value will be printed during the docker build process and can be accessed from within the enclave the while in the root folder with the command:
```console
gramine-sgx-get-token --output python3.token --sig python3.sig | grep mr_enclave
```
The lastest MRENCLAVE value for Cppcheck tool enclave was (base64): 
```
uIS6ZhE924aZ+F4REN2GmKzHkfPRqqHh0/HFMGmBnDU=
```