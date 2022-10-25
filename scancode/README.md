# Scancode tool enclave
ScanCode detects licenses, copyrights, package manifests & dependencies and more by scanning code, to discover and inventory open source and third-party packages used in your code.

Link to original repo: https://github.com/nexB/scancode-toolkit

## Changes
The CEST-platform run an unmodified version of ScanCode.

## MRENCLAVE
To verify that the software running inside the enclave is the same as in this repo, you can compare the MRENCLAVE value. The MRENCLAVE value uniquely identifies an enclave and will change if any software is modified. The MRENCLAVE value will be printed during the docker build process and can be accessed from within the enclave the while in the root folder with the command:
```console
gramine-sgx-get-token --output python3.token --sig python3.sig | grep mr_enclave
```
The lastest MRENCLAVE value for Dependency-Check tool enclave was (base64): 
```
wPoABPIuKeTgRpnyhAs/8xy8sV6xoKANN4l3BIyVtKI=
```
