# Checksec tool enclave
A simple tool to verify the security properties of your binaries.

Link to original repo: https://github.com/Wenzel/checksec.py

## Changes
The CEST-version has some minor changes from the original program to make it perform better in an enclave enviroment. It was made to run on a single thread and there was changes to how ldconfig is found on the system. 

For more details on these changes see the repo of the fork that is running in the enclave: https://github.com/hyker/checksec.py

## MRENCLAVE
To verify that the software running inside the enclave is the same as in this repo, you can compare the MRENCLAVE value. The MRENCLAVE value uniquely identifies an enclave and will change if any software is modified. The MRENCLAVE value will be printed during the docker build process and can be accessed from within the container the while in the root folder with the command:
```console
gramine-sgx-get-token --output python3.token --sig python3.sig | grep mr_enclave
```
The MRENCLAVE value will be printed in hexadecimal and needs to be converted to base64 to be compared with the value from the CEST-platform.

```console
gramine-sgx-get-token --output python3.token --sig python3.sig | sed -n 's/mr_enclave://p' |  xxd -r -p | base64
```

The latest MRENCLAVE value for Checksec tool enclave was (base64): 
```
9oGsIr/2/VBPrVHzkofDyLAop8uLrFY1v4lAV866Y0A=
```
## Building
To build everything locally you must first build the base image. 

To build this docker image, while being in root directory (where the script build_tool.sh is located) run the command:
```console
./build_tool.sh checksec
```
