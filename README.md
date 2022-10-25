# CEST-Tools
Tools of CEST

- [checksec](https://github.com/hyker/CEST-Tools/tree/main/checksec)
- [codechecker](https://github.com/hyker/CEST-Tools/tree/main/codechecker)
- [cppcheck](https://github.com/hyker/CEST-Tools/tree/main/cppcheck)
- [dependency-check](https://github.com/hyker/CEST-Tools/tree/main/dependency-check)
- [flawfinder](https://github.com/hyker/CEST-Tools/tree/main/flawfinder)

## using prebuilt image

- [checksec](https://hub.docker.com/layers/hyker/checksec-enclave/latest/images/sha256-cd520038a45fdde1fbc544c57714c77e504f3b5ec018a9a7bd256f0fda2c9965?context=repo)
- [codechecker](https://hub.docker.com/layers/hyker/codechecker-5g-air-simulator-enclave/latest/images/sha256-c4fc57f0c8f1319a64575eda64e51490fef225218075c73c70d0bc9b51c58fc7?context=repo)
- [cppcheck](https://hub.docker.com/layers/hyker/cppcheck-enclave/latest/images/sha256-2b71ae241c2d3d24245ba266aae3ed3164dead67f2026f03283ac4f5a0a2ee9a?context=repo)
- [dependency-check](https://hub.docker.com/layers/hyker/dependency-check-enclave/latest/images/sha256-6c6b62cd2e88309dc37b118be158abdffa254d339e709bce48cd3892793bc81d?context=repo)
- [flawfinder](https://hub.docker.com/layers/hyker/flawfinder-enclave/latest/images/sha256-2d1fc8da684e47ac7a5b96654552ca1665f94a5d7b0fd8dc0e3c656800afc4ce?context=repo)


## building yourself

### prerequsite
- git
- docker

`git clone git@github.com:hyker/CEST-Tools.git && cd CEST-Tools`

First make sure to build the baseimage

```
  docker build base-image/gamine-dcap -t hyker/gramine-dcap
```

To build each tool

```
  cp -R common <tool>/common
  docker build <tool> -t hyker/<tool>-tag
  rm -rf <tool>/common
```
