#!/bin/bash
#
# ACMED certificate watcher and renewer daemon.
# Helper script to build debian based docker image
#
# SPDX-FileCopyrightText: Nicolas Karageuzian
# SPDX-License-Identifier: FSFAP

set -euo pipefail

DIR="$( cd "$( dirname "$0" )/../.." >/dev/null 2>&1 && pwd )"

# Parse command line args
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target>"
    echo "Supported targets: stretch, buster"
    exit 1
fi
if [ "$1" == "buster" ]; then
    TARGET=buster
elif [ "$1" == "stretch" ]; then
    TARGET=stretch
else
    echo "Invalid target: $1"
    exit 1
fi

# Determine image
IMAGE=rust:1-$TARGET

function log {
    echo -e "\033[32;1m==> ${1}\033[0m"
}

# This or commit Dockerfile at project root
log "Prepare docker build"
cp $( dirname "$0" )/Dockerfile $DIR

cd $DIR

log "Build docker image"
docker build -t acmed:$TARGET --build-arg TARGET=$TARGET .

log "Successfully built image, Cleanup"

rm Dockerfile

log "Done! Find your binaries in the /usr/local/bin directory of image acmed:$TARGET."
