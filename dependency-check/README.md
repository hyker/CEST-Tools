# Dependency-Check tool enclave
OWASP dependency-check is a software composition analysis utility that detects publicly disclosed vulnerabilities in application dependencies.

Link to original repo: https://github.com/jeremylong/DependencyCheck

## Changes
The CEST-platform run an unmodified version of Dependency-Check. Some analyzers that require internet access are disabled. 

## MRENCLAVE
To verify that the software running inside the enclave is the same as in this repo, you can compare the MRENCLAVE value. The MRENCLAVE value uniquely identifies an enclave and will change if any software is modified. The MRENCLAVE value will be printed during the docker build process and can be accessed from within the container the while in the root folder with the command:
```console
gramine-sgx-get-token --output python3.token --sig python3.sig | grep mr_enclave
```
The MRENCLAVE value will be printed in hexadecimal and needs to be converted to base64 to be compared with the value from the CEST-platform.

The lastest MRENCLAVE value for Dependency-Check tool enclave was (base64): 
```
TNEDe1/0VJofKGDLZ3NvFLql3Wonql9k3OH3wzaPHnQ=
```
## Building
To build everything locally you must first build the base image. 

To build this docker image, while being in root directory (where the script build_tool.sh is located) run the command:
```console
./build_tool.sh dependency-check
```
