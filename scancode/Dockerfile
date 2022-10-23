FROM hyker/gramine-dcap

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y \
    wget \
    python3-dev=3.8.2-0ubuntu2 \
    python3-pip=20.0.2-5ubuntu1.6 \
    unzip=6.0-25ubuntu1 \
    bzip2=1.0.8-2 \
    xz-utils=5.2.4-1ubuntu1.1 \
    zlib1g=1:1.2.11.dfsg-2ubuntu1.5 \
    libxml2-dev=2.9.10+dfsg-5ubuntu0.20.04.4 \
    libxslt1-dev=1.1.34-4ubuntu0.20.04.1 \
    libgomp1=10.3.0-1ubuntu1~20.04 \
    libpopt0=1.16-14 \
 && rm -rf /var/lib/apt/lists/*

RUN pip3 install scancode-toolkit==31.1.1 pycryptodome tinyec
RUN scancode --help

RUN wget https://packages.microsoft.com/ubuntu/20.04/prod/pool/main/a/az-dcap-client/az-dcap-client_1.11.2_amd64.deb \
 && dpkg -i az-dcap-client_1.11.2_amd64.deb

RUN mkdir -p "$HOME"/.config/gramine/
RUN openssl genrsa -3 -out "$HOME"/.config/gramine/enclave-key.pem 3072

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

CMD ["/restart_aesm.sh ; exec gramine-sgx python3"] 