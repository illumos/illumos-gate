/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) RSA Data Security, Inc. created 1993, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

#ifndef _BIGMAXES_H_
#define _BIGMAXES_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_RSA_MODULUS_BITS 4096

#define BITS_TO_LEN(modulusBits) (((modulusBits) + 7) / 8)
#define RSA_PRIME_BITS(modulusBits) (((modulusBits) + 1) / 2)
#define RSA_PRIME_LEN(modulusBits) ((RSA_PRIME_BITS (modulusBits) + 7) / 8)
#define BITS_TO_WORDS(bits) ((bits >> 4) + 1)
#define LEN_TO_WORDS(len) ((len >> 1) + 1)

/* MAX_RSA_PRIME_BITS -- length in bits of the maximum allowed RSA prime
   MAX_RSA_MODULUS_LEN -- length in bytes of the maximum allowed RSA modulus,
                          in canonical format (no sign bit)
   MAX_RSA_PRIME_LEN -- length in bytes of the maximum allowed RSA prime, in
                        canonical format (no sign bit)
 */
#define MAX_RSA_PRIME_BITS RSA_PRIME_BITS (MAX_RSA_MODULUS_BITS)
#define MAX_RSA_PRIME_LEN RSA_PRIME_LEN (MAX_RSA_MODULUS_BITS)
#define MAX_RSA_MODULUS_LEN BITS_TO_LEN (MAX_RSA_MODULUS_BITS)

/* MAX_RSA_MODULUS_WORDS -- length in 16-bit words of the maximum allowed RSA
                            modulus, in bignum format (including sign bit)
   MAX_RSA_PRIME_WORDS -- length in 16-bit words of the maximum allowed RSA
                          prime, in bignum format (including sign bit)
 */

#define MAX_RSA_MODULUS_WORDS BITS_TO_WORDS (MAX_RSA_MODULUS_BITS)
#define MAX_RSA_PRIME_WORDS BITS_TO_WORDS (MAX_RSA_PRIME_BITS)

#ifdef __cplusplus
}
#endif

#endif
