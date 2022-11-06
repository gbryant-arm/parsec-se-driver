#!/usr/bin/env bash

# Copyright 2020 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Continuous Integration test script, executed by GitHub Actions on x86 and
# Travis CI on Arm64.

set -xeuf -o pipefail

# The clean up procedure is called when the script finished or is interrupted
cleanup () {
    echo "Shutdown Parsec and clean up"
    # Stop Parsec if running
    pkill -SIGTERM parsec || true
    # Stop tpm_server if running
    pkill tpm_server || true
    # Remove fake mapping and temp files
    rm -f "NVChip"
    rm -f "/tmp/parsec.sock"
    rm -rf parsec/mappings
    rm -f ci/c-tests/*psa_its

    if [ -z "$NO_CARGO_CLEAN" ]; then cargo clean; fi
}

trap cleanup EXIT

# Clippy needs the build to work, the include directory need to be available.
if [ ! -d "mbedtls" ]
then
	git clone https://github.com/ARMmbed/mbedtls.git

    # Compile Mbed Crypto for the test application
    pushd mbedtls
    git checkout v3.0.0
    ./scripts/config.py crypto
    ./scripts/config.py set MBEDTLS_PSA_CRYPTO_SE_C
    SHARED=1 make
    popd
fi


#################
# Static checks #
#################
# On native target clippy or fmt might not be available.
if cargo fmt -h; then
	cargo fmt --all -- --check
fi
if cargo clippy -h; then
	MBEDTLS_INCLUDE_DIR=$(pwd)/mbedtls/include cargo clippy --all-targets -- -D clippy::all -D clippy::cargo
fi

###########
# C Tests #
###########

# cp /tmp/NVChip .
# Start and configure TPM server
tpm_server &
sleep 5
# Ownership has already been taken with "tpm_pass".
tpm2_startup -c -T mssim

# Create the Parsec socket directory. This must be the default one.
# mkdir /run/parsec

# Install and run Parsec
if [ ! -d "parsec" ]
then
	git clone --branch attested-tls https://github.com/ionut-arm/parsec
fi
pushd ./parsec
cargo build --features tpm-provider --release
./target/release/parsec -c ../parsec-se-driver/ci/config.toml &
sleep 5
popd

if [ ! -d "parsec-tool" ]
then
	git clone --branch attested-tls https://github.com/ionut-arm/parsec-tool
fi
pushd parsec-tool
cargo build --release
PARSEC_SERVICE_ENDPOINT=unix:/tmp/parsec.sock ./target/release/parsec-tool create-endorsement > endorsement.json
popd

# Build the driver, clean before to force dynamic linking
# cargo clean
MBEDTLS_INCLUDE_DIR=$(pwd)/mbedtls/include cargo build --release

# Compile and run the C application
export MBED_TLS_PATH=$(pwd)/mbedtls
make -C ci/c-tests clean 
make -C ci/c-tests run 
