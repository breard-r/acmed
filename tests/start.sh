#!/usr/bin/env bash

TEST_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
TEST_OUTPUT_DIR="${TEST_DIR}/output"
DNS_SERVER="${DNS_SERVER:-"127.0.0.1"}"
PEBBLE_BIN="${PEBBLE_BIN:-"$HOME/go/bin/pebble"}"
PEBBLE_BIN_SHORT="$(basename "$PEBBLE_BIN")"
PEBBLE_CONFIG="${TEST_OUTPUT_DIR}/pebble-config.json"
PEBBLE_CONFIG_TPL="${TEST_DIR}/assets/pebble-config.tpl.json"

# Prepare the output directory
rm -rf "$TEST_OUTPUT_DIR"
mkdir -p "$TEST_OUTPUT_DIR"
sed "s@{{TEST_DIR}}@$TEST_DIR@g" "$PEBBLE_CONFIG_TPL" >"$PEBBLE_CONFIG"

# Display settings
echo "Pebble binary: $PEBBLE_BIN"
echo "DNS server: $DNS_SERVER"
echo "Test directory: $TEST_DIR"
echo "Test output directory: $TEST_OUTPUT_DIR"
echo "Pebble configuration:"
cat "$PEBBLE_CONFIG"

# Run Pebble and ACMEd
"$PEBBLE_BIN" -config "$PEBBLE_CONFIG" -dnsserver "$DNS_SERVER" -strict &
sleep 15

# Clean before exit
pkill "$PEBBLE_BIN_SHORT"
rm -rf "$TEST_OUTPUT_DIR"
exit 0
