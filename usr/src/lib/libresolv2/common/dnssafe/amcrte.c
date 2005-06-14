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

#include "port_before.h"
#include "global.h"
#include "algae.h"
#include "bsafe2.h"
#include "balgmeth.h"
#include "crt2.h"
#include "amencdec.h"
#include "port_after.h"

static int RSA_CRT2Query PROTO_LIST ((unsigned int *, POINTER, POINTER));
static int RSA_CRT2Init PROTO_LIST
  ((POINTER, POINTER, POINTER, A_SURRENDER_CTX *));
static int RSA_CRT2Update PROTO_LIST
  ((POINTER, unsigned char *, unsigned int *, unsigned int,
    const unsigned char *, unsigned int, A_SURRENDER_CTX *));
static int RSA_CRT2Final PROTO_LIST
  ((POINTER, unsigned char *, unsigned int *, unsigned int,
    A_SURRENDER_CTX *));
static int RSA_CRT2GetMaxOutputLen PROTO_LIST
  ((POINTER, unsigned int *, unsigned int));
static int RSA_CRT2GetBlockLen PROTO_LIST ((POINTER, unsigned int *));

extern struct B_AlgorithmInfoType AIT_RSAPrivate;
extern struct B_KeyInfoType KIT_RSA_CRT;

static A_ENCRYPT_DECRYPT_ALGA A_RSA_CRT2_CRYPT = {
  RSA_CRT2Query, RSA_CRT2Init, RSA_CRT2Update, RSA_CRT2Final,
  RSA_CRT2GetMaxOutputLen, RSA_CRT2GetBlockLen
};

B_ALGORITHM_METHOD AM_RSA_CRT_DECRYPT =
  {&AIT_RSAPrivate, 0, &KIT_RSA_CRT, (POINTER)&A_RSA_CRT2_CRYPT};
B_ALGORITHM_METHOD AM_RSA_CRT_ENCRYPT =
  {&AIT_RSAPrivate, 1, &KIT_RSA_CRT, (POINTER)&A_RSA_CRT2_CRYPT};

static int RSA_CRT2Query (contextLen, key, params)
unsigned int *contextLen;
POINTER key;
POINTER params;
{
UNUSED_ARG (params)

  if (A_IntegerBits
      (((A_RSA_CRT_KEY *)key)->modulus.data,
       ((A_RSA_CRT_KEY *)key)->modulus.len) > MAX_RSA_MODULUS_BITS)
    /* Key size is too big to handle. */
    return (AE_MODULUS_LEN);

  *contextLen = sizeof (A_RSA_CRT2_CTX);
  return (0);
}

static int RSA_CRT2Init (context, key, params, surrenderContext)
POINTER context;
POINTER key;
POINTER params;
A_SURRENDER_CTX *surrenderContext;
{
UNUSED_ARG (params)
UNUSED_ARG (surrenderContext)

  return (A_RSA_CRT2Init ((A_RSA_CRT2_CTX *)context, (A_RSA_CRT_KEY *)key));
}

static int RSA_CRT2Update
  (context, output, outputLen, maxOutputLen, input, inputLen, surrenderContext)
POINTER context;
unsigned char *output;
unsigned int *outputLen;
unsigned int maxOutputLen;
const unsigned char *input;
unsigned int inputLen;
A_SURRENDER_CTX *surrenderContext;
{
  return (A_RSA_CRT2Update
          ((A_RSA_CRT2_CTX *)context, output, outputLen, maxOutputLen, input,
           inputLen, surrenderContext));
}

static int RSA_CRT2Final
  (context, output, outputLen, maxOutputLen, surrenderContext)
POINTER context;
unsigned char *output;
unsigned int *outputLen;
unsigned int maxOutputLen;
A_SURRENDER_CTX * surrenderContext;
{
UNUSED_ARG (output)
UNUSED_ARG (maxOutputLen)
UNUSED_ARG (surrenderContext)

  *outputLen = 0;
  return (A_RSA_CRT2Final ((A_RSA_CRT2_CTX *)context));
}

static int RSA_CRT2GetMaxOutputLen (context, outputLen, inputLen)
POINTER context;
unsigned int *outputLen;
unsigned int inputLen;
{
  *outputLen = A_RSA_CRT2_MAX_OUTPUT_LEN ((A_RSA_CRT2_CTX *)context, inputLen);
  return (0);
}

static int RSA_CRT2GetBlockLen (context, blockLen)
POINTER context;
unsigned int *blockLen;
{
  *blockLen = A_RSA_CRT2_BLOCK_LEN ((A_RSA_CRT2_CTX *)context);
  return(0);
}
