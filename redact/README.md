To verify that the software running inside the enclave is the same as in this repo, you can compare the MRENCLAVE value. The MRENCLAVE value uniquely identifies an enclave and will change if any software is modified. The MRENCLAVE value will be printed during the docker build process and can be accessed from within the container the while in the root folder with the command:

gramine-sgx-get-token --output python3.token --sig python3.sig | grep mr_enclave
The MRENCLAVE value will be printed in hexadecimal and needs to be converted to base64 to be compared with the value from the CEST-platform.

gramine-sgx-get-token --output python3.token --sig python3.sig | sed -n 's/mr_enclave://p' |  xxd -r -p | base64
The latest MRENCLAVE value for Checksec tool enclave was (base64):

hUv9l3jpQE+1/DUXHaPIknaYgtbn2BN0hIG+QIs3xI0=
