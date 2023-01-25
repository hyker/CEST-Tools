# Redaction Enclave
Redaction Enclave is a safe way of removing sensitive parts of reports created by other tools in this repository

## MRENCLAVE
To verify that the software running inside the enclave is the same as in this repo, you can compare the MRENCLAVE value. The MRENCLAVE value uniquely identifies an enclave and will change if any software is modified. The MRENCLAVE value will be printed during the docker build process and can be accessed from within the container the while in the root folder with the command:
```console
gramine-sgx-get-token --output python3.token --sig python3.sig | grep mr_enclave
```
The MRENCLAVE value will be printed in hexadecimal and needs to be converted to base64 to be compared with the value from the CEST-platform.

The lastest MRENCLAVE value for redact tool enclave was (base64): 
```
7ctVUuGfWGA7Nd5vyQ80qDy0zeLm8xcX12inyvr5aUg=
```

