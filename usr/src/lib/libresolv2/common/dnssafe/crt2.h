/*
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) RSA Data Security, Inc. created 1994, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

#ifndef _RSA_H_
#define _RSA_H_ 1

#include "bigmaxes.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Note, these are only valid after a call to A_RSA_CRT2Init.
 */
#define A_RSA_CRT2_BLOCK_LEN(context) ((context)->blockLen)
#define A_RSA_CRT2_MAX_OUTPUT_LEN(context, inputLen)\
  (inputLen) + (((inputLen) % (context)->blockLen) ?\
                (context)->blockLen - ((inputLen) % (context)->blockLen) : 0)

typedef struct {
  unsigned int blockLen;           /* total size of the block to be computed */
  unsigned char input[MAX_RSA_MODULUS_LEN];
  unsigned int inputLen;
  unsigned int primeWords;
  UINT2 modulus[2 * MAX_RSA_PRIME_WORDS];
  UINT2 primeP[MAX_RSA_PRIME_WORDS];
  UINT2 primeQ[MAX_RSA_PRIME_WORDS];
  UINT2 exponentP[MAX_RSA_PRIME_WORDS];
  UINT2 exponentQ[MAX_RSA_PRIME_WORDS];
  UINT2 coefficient[MAX_RSA_PRIME_WORDS];
} A_RSA_CRT2_CTX;

int A_RSA_CRT2Init PROTO_LIST ((A_RSA_CRT2_CTX *, A_RSA_CRT_KEY *));
int A_RSA_CRT2Update PROTO_LIST
  ((A_RSA_CRT2_CTX *, unsigned char *, unsigned int *, unsigned int,
    const unsigned char *, unsigned int, A_SURRENDER_CTX *));
int A_RSA_CRT2Final PROTO_LIST ((A_RSA_CRT2_CTX *));
void A_RSA_CRT2GetMaxOutputLen PROTO_LIST
  ((A_RSA_CRT2_CTX *, unsigned int *, unsigned int));

#ifdef __cplusplus
}
#endif

#endif
