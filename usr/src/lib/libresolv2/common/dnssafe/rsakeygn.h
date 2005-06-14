/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) RSA Data Security, Inc. created 1994, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

#ifndef _RSAKEYGN_H_
#define _RSAKEYGN_H_ 1

#include "bigmaxes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MIN_RSA_MODULUS_BITS 256

/* Need randomBlock to hold bytes for two UINT2 prime number arrays each,
     of length primeWords = BITS_TO_WORDS (RSA_PRIME_BITS (modulusBits)). */
#define A_RSA_KEY_GEN_RANDOM_BLOCK_LEN(modulusBits) \
  (4 * BITS_TO_WORDS (RSA_PRIME_BITS (modulusBits)))

/* Note that the scratch area for the output integers is allocated
     in the context after the RSA_KEY_GEN_CTX.
 */
typedef struct {
  unsigned int modulusBits;
  UINT2 bigModulus[MAX_RSA_MODULUS_WORDS];
  UINT2 bigPublicExponent[MAX_RSA_MODULUS_WORDS];
  UINT2 bigPrivateExponent[MAX_RSA_MODULUS_WORDS];
  UINT2 bigPrime1[MAX_RSA_PRIME_WORDS];
  UINT2 bigPrime2[MAX_RSA_PRIME_WORDS];
  UINT2 bigExponentP[MAX_RSA_PRIME_WORDS];
  UINT2 bigExponentQ[MAX_RSA_PRIME_WORDS];
  UINT2 bigCoefficient[MAX_RSA_PRIME_WORDS];
  A_PKCS_RSA_PRIVATE_KEY result;
  unsigned char resultBuffer
    [3 * BITS_TO_LEN (MAX_RSA_MODULUS_BITS) +
     5 * RSA_PRIME_LEN (MAX_RSA_MODULUS_BITS)];
} A_RSA_KEY_GEN_CTX;

int A_RSAKeyGenInit PROTO_LIST ((A_RSA_KEY_GEN_CTX *, A_RSA_KEY_GEN_PARAMS *));
int A_RSAKeyGen PROTO_LIST
  ((A_RSA_KEY_GEN_CTX  *, A_PKCS_RSA_PRIVATE_KEY **, unsigned char *,
    A_SURRENDER_CTX *));

#ifdef __cplusplus
}
#endif

#endif

