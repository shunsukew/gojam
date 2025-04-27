#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define RING_COMMITMENT_SIZE 144

#define PUBKEY_SIZE 32

#define SECRET_SIZE 32

#define RING_VRF_SIGNATURE_SIZE 784

#define OUTPUT_HASH_SIZE 32

bool new_secret_from_seed(const unsigned char *seed_ptr,
                          size_t seed_len,
                          unsigned char *secret_out_ptr);

bool new_public_key_from_secret(const unsigned char *secret_ptr, unsigned char *public_out_ptr);

bool new_ring_commitment(const unsigned char (*ring_ptr)[PUBKEY_SIZE],
                         size_t ring_len,
                         unsigned char *commitment_out_ptr);

bool ring_vrf_sign(const unsigned char (*ring_ptr)[PUBKEY_SIZE],
                   size_t ring_len,
                   const unsigned char *prover_idx,
                   const unsigned char *prover_secret_ptr,
                   const unsigned char *vrf_input_data_ptr,
                   size_t vrf_input_data_len,
                   const unsigned char *aux_data_ptr,
                   size_t aux_data_len,
                   unsigned char *signature_out_ptr);

bool ring_vrf_verify(const unsigned char *vrf_input_data_ptr,
                     size_t vrf_input_data_len,
                     const unsigned char *aux_data_ptr,
                     size_t aux_data_len,
                     const unsigned char *ring_commitment_ptr,
                     const unsigned char *signature_ptr,
                     unsigned char *output_hash_out_ptr);
