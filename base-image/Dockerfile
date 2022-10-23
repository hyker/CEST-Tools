FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    autoconf \
    automake \
    build-essential \
    cmake \
    debhelper \
    gettext-base \
    git \
    gnupg2 \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    libprotobuf-c-dev \
    protobuf-c-compiler \
    python3-protobuf \
    libssl-dev \
    libtool \
    moreutils \
    ocaml \
    ocamlbuild \
    perl \
    protobuf-compiler \
    python-is-python3 \
    reprepro \
    unzip \
    wget \
 && rm -rf /var/lib/apt/lists/*

RUN echo "ca_directory=/etc/ssl/certs" >> /etc/wgetrc && \
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key --no-check-certificate | apt-key add -

# Install SGX PSW
ARG PSW_VERSION=2.15.101.1
ARG DCAP_VERSION=1.12.101.1
RUN apt-get update && apt-get install -y \
    libsgx-launch-dev=$PSW_VERSION-focal1 \
    libsgx-epid-dev=$PSW_VERSION-focal1 \
    libsgx-quote-ex-dev=$PSW_VERSION-focal1 \
    libsgx-urts=$PSW_VERSION-focal1 \
    libsgx-enclave-common=$PSW_VERSION-focal1 \
    libsgx-uae-service=$PSW_VERSION-focal1 \
    libsgx-ae-epid=$PSW_VERSION-focal1 \
    libsgx-ae-le=$PSW_VERSION-focal1 \
    libsgx-ae-pce=$PSW_VERSION-focal1 \
    libsgx-aesm-launch-plugin=$PSW_VERSION-focal1 \
    sgx-aesm-service=$PSW_VERSION-focal1 \
    libsgx-aesm-launch-plugin=$PSW_VERSION-focal1 \
    libsgx-aesm-pce-plugin=$PSW_VERSION-focal1 \
    libsgx-aesm-ecdsa-plugin=$PSW_VERSION-focal1 \
    libsgx-aesm-epid-plugin=$PSW_VERSION-focal1 \
    libsgx-aesm-quote-ex-plugin=$PSW_VERSION-focal1 \
    libsgx-dcap-quote-verify=$DCAP_VERSION-focal1 \
    libsgx-dcap-quote-verify-dev=$DCAP_VERSION-focal1 \
    libsgx-dcap-ql=$DCAP_VERSION-focal1 \
    libsgx-dcap-ql-dev=$DCAP_VERSION-focal1 \
    libsgx-epid=$PSW_VERSION-focal1 \
    libsgx-quote-ex=$PSW_VERSION-focal1 \
    libsgx-pce-logic=$DCAP_VERSION-focal1 \
    libsgx-qe3-logic=$DCAP_VERSION-focal1 \
    libsgx-launch=$PSW_VERSION-focal1 \
    libsgx-dcap-default-qpl=$DCAP_VERSION-focal1 \
 && rm -rf /var/lib/apt/lists/* \
 && ln -s /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so.1 /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so

# Install SGX SDK
RUN cd /tmp \
 && git clone -b sgx_2.15.1 https://github.com/intel/linux-sgx \
 && mkdir /etc/init \
 && cd linux-sgx \
 && make preparation \
 && ls -la external/toolset/ubuntu20.04/ \
 && cp external/toolset/ubuntu20.04/* /usr/local/bin \
 && make sdk \
 && make sdk_install_pkg \
 && mkdir -p /opt/intel \
 && cd /opt/intel \
 && yes yes | /tmp/linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_*.bin \
 && rm -rf /tmp/linux-sgx

 RUN mkdir -p /var/run/aesmd

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
