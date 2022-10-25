# Dependency-Check tool enclave
OWASP dependency-check is a software composition analysis utility that detects publicly disclosed vulnerabilities in application dependencies.

Link to original repo: https://github.com/jeremylong/DependencyCheck

## Changes
The CEST-platform run an unmodified version of Dependency-Check. Some analyzers that require internet access are disabled. 

## MRENCLAVE
To verify that the software running inside the enclave is the same as in this repo, you can compare the MRENCALVE value. The MRENCLAVE value uniquely identifies an enclave and will change if any software is modified. The MRENCLAVE value will be printed during the docker build process and can be accessed from within the enclave the while in the root folder with the command:
```console
gramine-sgx-get-token --output python3.token --sig python3.sig | grep mr_enclave
```
The lastest MRENCLAVE value for Dependency-Check tool enclave was (base64): 
```
Rrue4RlBHmCJx81Qx7XF0dykKt1Ch3QWq6SJklcE+c0=
```
