#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

bool new_ring_verifier_commitment(const unsigned char (*pubkeys_ptr)[32],
                                  unsigned int pubkeys_len,
                                  unsigned char *out_ptr);
