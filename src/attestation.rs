// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{client_error_to_psa_status, key_slot_to_key_name, PARSEC_BASIC_CLIENT};
use psa_crypto::ffi::{psa_key_slot_number_t, psa_status_t, PSA_SUCCESS};

/// Attest a key
///
/// # Safety
///
/// DO NOT USE THIS
#[no_mangle]
pub unsafe extern "C" fn parsec_attest_key(
    key_slot: psa_key_slot_number_t,
    _mech: u32,
    challenge: *const u8,
    challenge_length: usize,
    attestation_token: *mut u8,
    _attestation_token_size: usize,
    attestation_token_length: *mut usize,
) -> psa_status_t {
    // Get tokens from service
    let token = match PARSEC_BASIC_CLIENT.read().unwrap().attest_key(
        key_slot_to_key_name(key_slot),
        None,
        std::slice::from_raw_parts(challenge, challenge_length).to_vec(),
    ) {
        Ok(token) => token,
        Err(e) => return client_error_to_psa_status(e),
    };
    let slice: &mut [u8] = std::slice::from_raw_parts_mut(attestation_token, token.len());
    slice.copy_from_slice(&token);
    *attestation_token_length = token.len();

    PSA_SUCCESS
}
