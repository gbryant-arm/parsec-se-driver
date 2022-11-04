// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

#ifndef PARSEC_CLIENT_H
#define PARSEC_CLIENT_H

#include "psa/crypto_types.h"
#include <stddef.h>

typedef uint32_t parsec_attest_mechanism_t;

// TODO: add init function

psa_status_t parsec_attest_key(psa_key_id_t attested_key,
                               parsec_attest_mechanism_t mech,
                               const uint8_t *challenge,
                               size_t challenge_length,
                               uint8_t *attestation_token,
                               size_t attestation_token_size,
                               size_t *attestation_token_length);

#endif /* PARSEC_CLIENT_H */
