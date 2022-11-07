# Codechecker tool enclave
CodeChecker is an analyzer tooling, defect database and viewer extension for the Clang Static Analyzer and Clang Tidy

Link to original repo: https://github.com/Ericsson/codechecker

## Changes
The CEST-version has some minor changes from the original program to make it perform better in an enclave enviroment. The analysis runs as a single process instead of using multiprocessing and the use of preexec_fn was removed because it is not thread safe, for more details see the file "changes" in this folder.

## MRENCLAVE
To verify that the software running inside the enclave is the same as in this repo, you can compare the MRENCLAVE value. The MRENCLAVE value uniquely identifies an enclave and will change if any software is modified. The MRENCLAVE value will be printed during the docker build process and can be accessed from within the container the while in the root folder with the command:
```console
gramine-sgx-get-token --output python3.token --sig python3.sig | grep mr_enclave
```
The lastest MRENCLAVE value for CodeChecker tool enclave was (hex): 
```
46ac0347fc52bcfc445320215ba1a08c33eb986f245b7e9622875cb8f8f1ac37
```
## Building
To build everything locally you must first build the base image. 

To build this docker image, while being in root directory (where the script build_tool.sh is located) run the command:
```console
./build_tool.sh codechecker
```
