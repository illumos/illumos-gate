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

/* Note, these are only valid after a call to A_RSAInit.
 */
#define A_RSA_BLOCK_LEN(context) ((context)->blockLen)
#define A_RSA_MAX_OUTPUT_LEN(context, inputLen)\
  (inputLen) + (((inputLen) % (context)->blockLen) ?\
                (context)->blockLen - ((inputLen) % (context)->blockLen) : 0)

typedef struct {
  unsigned int blockLen;          /* total size for the block to be computed */
  unsigned char input[MAX_RSA_MODULUS_LEN];
  unsigned int inputLen;
  unsigned int modulusWords;
  UINT2 modulus[MAX_RSA_MODULUS_WORDS];
  UINT2 exponent[MAX_RSA_MODULUS_WORDS];
} A_RSA_CTX;

int A_RSAInit PROTO_LIST ((A_RSA_CTX *, A_RSA_KEY *));
int A_RSAUpdate PROTO_LIST
  ((A_RSA_CTX *, unsigned char *, unsigned int *, unsigned int,
    const unsigned char *, unsigned int, A_SURRENDER_CTX *));
int A_RSAFinal PROTO_LIST ((A_RSA_CTX *));

#ifdef __cplusplus
}
#endif

#endif
