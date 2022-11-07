#!/bin/sh
set -e

FOLDER="${1:-cppcheck}"
DEPLOYMENT="$FOLDER-enclave"

cp -R common $FOLDER/common
docker build $FOLDER -t hyker/$DEPLOYMENT
rm -rf $FOLDER/common
