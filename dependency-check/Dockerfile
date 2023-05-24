FROM hyker/gramine-dcap

ENV DEBIAN_FRONTEND noninteractive

RUN  apt-get update && apt-get install -y \
  wget curl git build-essential cmake \
  libprotobuf-c-dev=1.3.3-1ubuntu0.1 \
  python3-dev=3.8.2-0ubuntu2 \
  unzip=6.0-25ubuntu1 \
  python3-xmltodict=0.12.0-1 \
  python3-pip=20.0.2-5ubuntu1.6 \
  openjdk-11-jdk=11.0.17+8-1ubuntu2~20.04 \
  xxd=2:8.1.2269-1ubuntu5.11 \
 && rm -rf /var/lib/apt/lists/*

RUN pip3 install pycryptodome tinyec

RUN wget https://packages.microsoft.com/ubuntu/20.04/prod/pool/main/a/az-dcap-client/az-dcap-client_1.11.2_amd64.deb \
 && dpkg -i az-dcap-client_1.11.2_amd64.deb


RUN mkdir -p "$HOME"/.config/gramine/
RUN openssl genrsa -3 -out "$HOME"/.config/gramine/enclave-key.pem 3072

RUN wget https://github.com/jeremylong/DependencyCheck/releases/download/v7.2.1/dependency-check-7.2.1-release.zip
RUN unzip /dependency-check-7.2.1-release.zip
RUN /dependency-check/bin/dependency-check.sh --updateonly

COPY common/aesmd.conf /etc/aesmd.conf
COPY common/sgx_default_qcnl.conf /etc/sgx_default_qcnl.conf
RUN mkdir -p /script
COPY common/run.py /script/run.py
COPY tool.py /script/tool.py
RUN mkdir /encrypted
RUN mkdir /toe
RUN mkdir /result
COPY common/cestcrypto.py /script/cestcrypto.py
RUN mkdir -p /pod-storage/DependencyChecker7.2.1/

#RUN cp -r /dependency-check/data/ /dependency-check/databackup/

WORKDIR /
RUN gramine-argv-serializer "python" "/script/run.py" > /gramine_args.txt
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

#CMD gramine-sgx java -Xmx4G -classpath /dependency-check/plugins/*:/dependency-check/lib/* -Dapp.name=dependency-check -Dapp.pid=1 -Dapp.repo=/dependency-check/lib -Dapp.home=/dependency-check -Dbasedir=/dependency-check org.owasp.dependencycheck.App --noupdate -s /toe -o /toe --disableOssIndex --format XML
