#!/bin/bash

source /opt/intel/sgxsdk/environment
if ! pgrep "aesm_service" > /dev/null ; then
  LD_LIBRARY_PATH="/opt/intel/sgx-aesm-service/aesm:$LD_LIBRARY_PATH" nohup /opt/intel/sgx-aesm-service/aesm/aesm_service --no-daemon >/dev/null 2>&1 &
fi
exec "$@"