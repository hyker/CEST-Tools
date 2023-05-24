FROM hyker/gramine-dcap

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y \
    wget=1.20.3-1ubuntu1 \
    curl=7.68.0-1ubuntu2.15 \
    python3-dev=3.8.2-0ubuntu2 \
    python3-pip=20.0.2-5ubuntu1.6 \
    unzip=6.0-25ubuntu1 \
    build-essential=12.8ubuntu1.1 \
    autoconf=2.69-11.1 \
    clang=1:10.0-50~exp1 \
    clang-tools=1:10.0-50~exp1 \
    clang-tidy=1:10.0-50~exp1 \
    gcc-multilib=4:9.3.0-1ubuntu2 \
    libssl-dev=1.1.1f-1ubuntu2.16 \
    pkg-config=0.29.1-0ubuntu4 \
    cmake=3.16.3-1ubuntu1.20.04.1 \
    libarmadillo-dev=1:9.800.4+dfsg-1build1 \
    xxd=2:8.1.2269-1ubuntu5.11 \
    libfftw3-dev libmbedtls-dev libboost-program-options-dev libconfig++-dev libsctp-dev git \
 && rm -rf /var/lib/apt/lists/*

RUN pip3 install codechecker==6.18.2 pycryptodome tinyec

WORKDIR /

RUN wget https://packages.microsoft.com/ubuntu/20.04/prod/pool/main/a/az-dcap-client/az-dcap-client_1.11.2_amd64.deb \
 && dpkg -i az-dcap-client_1.11.2_amd64.deb


# RUN ln -sf /usr/bin/clang++ /usr/bin/c++ \
# && ln -sf /usr/bin/clang /usr/bin/cc

COPY patches/analysis_manager.py /usr/local/lib/python3.8/dist-packages/codechecker_analyzer/analysis_manager.py
COPY patches/analyzer.py /usr/local/lib/python3.8/dist-packages/codechecker_analyzer/analyzer.py
COPY patches/zipfile.py /usr/lib/python3.8/zipfile.py
COPY patches/analyzer_base.py /usr/local/lib/python3.8/dist-packages/codechecker_analyzer/analyzers/analyzer_base.py
COPY patches/plist.py /usr/local/lib/python3.8/dist-packages/codechecker_report_converter/report/parser/plist.py

RUN mkdir -p "$HOME"/.config/gramine/
RUN openssl genrsa -3 -out "$HOME"/.config/gramine/enclave-key.pem 3072

COPY common/aesmd.conf /etc/aesmd.conf
COPY common/sgx_default_qcnl.conf /etc/sgx_default_qcnl.conf
RUN mkdir -p /script
COPY common/run.py /script/run.py
COPY tool.py /script/tool.py
RUN mkdir /encrypted
RUN mkdir /toe
RUN mkdir /result
COPY common/cestcrypto.py /script/cestcrypto.py

RUN mkdir /extratmp

WORKDIR /
RUN gramine-argv-serializer "python3" "/script/run.py" > /gramine_args.txt
COPY manifest.template manifest.template

RUN gramine-manifest \
    -Dlog_level=warning \
    -Dentrypoint=$(realpath $(which python3)) \
    -Darch_libdir=/lib/$(gcc -dumpmachine) \
    -Dra_client_spid= \
    -Dra_client_linkable=0 \
    manifest.template > python3.manifest
RUN gramine-sgx-sign \
    --key "$HOME"/.config/gramine/enclave-key.pem \
    --manifest python3.manifest \
    --output python3.manifest.sgx
RUN gramine-sgx-get-token \
    --output python3.token \
    --sig python3.sig

CMD ["/restart_aesm.sh ; mkdir /dev/sgx ; ln -s /dev/sgx_enclave /dev/sgx/enclave ; ln -s /dev/sgx_provision /dev/sgx/provision ; gramine-sgx python3"]
