# Copyright 2020 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

default: run

main.o:
	gcc -Wall -c -I../../include -I$(MBED_TLS_PATH)/include main.c

test-app: main.o
	gcc -Wall -o test-app main.o -L$(MBED_TLS_PATH)/library -L../../target/release -l:libparsec_se_driver.a -lmbedcrypto -lm -pthread -ldl

run: test-app
	PARSEC_SERVICE_ENDPOINT=unix:/tmp/parsec.sock RUST_LOG=info LD_LIBRARY_PATH=$(MBED_TLS_PATH)/library:$(LD_LIBRARY_PATH) ./test-app

clean:
	rm -rf test-app main.o
	rm -rf *.psa_its
