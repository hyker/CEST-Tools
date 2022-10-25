# Codechecker tool enclave
CodeChecker is an analyzer tooling, defect database and viewer extension for the Clang Static Analyzer and Clang Tidy

Link to original repo: https://github.com/Ericsson/codechecker

## Changes
The CEST-version has some minor changes from the original program to make it perform better in an encalve enviroment. The analysis runs as a single process instead of using multiprocessing and the use of preexec_fn was removed because it is not thread safe, for more details see the file "changes" in this folder.

## MRENCLAVE
To verify that the software running inside the enclave is the same as in this repo, you can compare the MRENCALVE value. The MRENCLAVE value uniquely identifies an enclave and will change if any software is modified. The MRENCLAVE value will be printed during the docker build process and can be accessed from within the enclave the while in the root folder with the command:
```console
gramine-sgx-get-token --output python3.token --sig python3.sig | grep mr_enclave
```
The lastest MRENCLAVE value for CodeChecker tool enclave was (base64): 
```
DnE5mrPnTT0aE7ocEFO6kF6VVoBKkYU1CVM+0sK8JO8=
```
