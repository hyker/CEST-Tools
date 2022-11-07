# Base image
This is the base image for all the docker containers with sgx capability on the CEST-platform. It is primarily base on the [gramine docker image](https://github.com/gramineproject/gramine/tree/master/packaging/docker).
## Building
To build the docker image, while being in this directory run the command:
```console
docker build . -t hyker/gramine-dcap
```
