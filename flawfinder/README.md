# Flawfinder tool enclave
Flawfinder is a simple program that scans C/C++ source code and reports potential security flaws. It can be a useful tool for examining software for vulnerabilities, and it can also serve as a simple introduction to static source code analysis tools more generally. It is designed to be easy to install and use. Flawfinder supports the Common Weakness Enumeration (CWE) and is officially CWE-Compatible.

Link to original repo: https://github.com/david-a-wheeler/flawfinder

## Changes
The CEST-platform run an unmodified version of Flawfinder.

## MRENCLAVE
To verify that the software running inside the enclave is the same as in this repo, you can compare the MRENCALVE value. The MRENCLAVE value uniquely identifies an enclave and will change if any software is modified. The MRENCLAVE value will be printed during the docker build process and can be accessed from within the enclave the while in the root folder with the command:
```console
gramine-sgx-get-token --output python3.token --sig python3.sig | grep mr_enclave
```
The lastest MRENCLAVE value for Dependency-Check tool enclave was (base64): 
```
M9Hd5M13HjdxadtalmYEIsbS6HqbJHFP+5Ht9VFKPuY=
```
