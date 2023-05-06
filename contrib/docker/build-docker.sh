#!/bin/bash
set -euo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../.." >/dev/null 2>&1 && pwd )"

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

log "Pulling image $IMAGE..."
docker pull $IMAGE

log "Starting container..."
CID=$(docker run --rm -td $IMAGE)

log "Copying project files..."
docker cp "$DIR" "$CID":/code/

log "Starting build..."
docker exec "$CID" /bin/bash -c "cd /code && cargo build --release"

log "Copying binaries..."
mkdir -p target/docker/$TARGET/
docker cp "$CID":/code/target/release/acmed target/docker/$TARGET/
docker cp "$CID":/code/target/release/tacd target/docker/$TARGET/

log "Stopping and removing container..."
docker stop "$CID"

log "Done! Find your binaries in the target/docker/$TARGET/ directory."
