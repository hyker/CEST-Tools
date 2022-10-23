FROM hyker/gramine-dcap

RUN apt update && apt install -y curl=7.68.0-1ubuntu2.13 wget git


RUN apt install -y \
   # gramine-dcap \
    python3-dev=3.8.2-0ubuntu2 \
    python3-pip=20.0.2-5ubuntu1.6 \
    unzip=6.0-25ubuntu1 \
 && rm -rf /var/lib/apt/lists/*

RUN wget https://packages.microsoft.com/ubuntu/20.04/prod/pool/main/a/az-dcap-client/az-dcap-client_1.11.2_amd64.deb \
 && dpkg -i az-dcap-client_1.11.2_amd64.deb

WORKDIR /tmp
RUN git clone https://github.com/hyker/checksec.py.git \
 && cd checksec.py \
 && git checkout 6d8847e9 \
 && python3 setup.py sdist \
 && python3 setup.py bdist_wheel \
 && pip3 install . \
 && cd .. \
 && rm -rf checksec.py

RUN pip3 install pycryptodome tinyec

RUN mkdir -p "$HOME"/.config/gramine/
RUN openssl genrsa -3 -out "$HOME"/.config/gramine/enclave-key.pem 3072

#COPY common/aesmd.conf /etc/aesmd.conf
#COPY common/sgx_default_qcnl.conf /etc/sgx_default_qcnl.conf
RUN mkdir -p /script
COPY common/run.py /script/run.py
COPY tool.py /script/tool.py
RUN mkdir /encrypted
COPY common/cestcrypto.py /script/cestcrypto.py

RUN mkdir /extratmp

WORKDIR /
RUN gramine-argv-serializer "python3" "/script/run.py" > /gramine_args.txt
COPY manifest.template manifest.template

RUN gramine-manifest \
    -Dlog_level=error \
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

#CMD python3 /script/run.py
CMD ["/restart_aesm.sh ; exec gramine-sgx python3"]