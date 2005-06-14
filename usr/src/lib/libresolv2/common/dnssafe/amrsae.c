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
#include "rsa.h"
#include "amencdec.h"
#include "port_after.h"

static int RSAQuery PROTO_LIST ((unsigned int *, POINTER, POINTER));
static int RSAInit PROTO_LIST ((POINTER, POINTER, POINTER, A_SURRENDER_CTX *));
static int RSAUpdate PROTO_LIST
  ((POINTER, unsigned char *, unsigned int *, unsigned int,
    const unsigned char *, unsigned int, A_SURRENDER_CTX *));
static int RSAFinal PROTO_LIST
  ((POINTER, unsigned char *, unsigned int *, unsigned int,
    A_SURRENDER_CTX *));
static int RSAGetMaxOutputLen PROTO_LIST
  ((POINTER, unsigned int *, unsigned int));
static int RSAGetBlockLen PROTO_LIST ((POINTER, unsigned int *));

extern struct B_AlgorithmInfoType AIT_RSAPublic;
extern struct B_KeyInfoType KIT_RSAPublic;

static A_ENCRYPT_DECRYPT_ALGA A_RSA_CRYPT = {
  RSAQuery, RSAInit, RSAUpdate, RSAFinal, RSAGetMaxOutputLen, RSAGetBlockLen
};

B_ALGORITHM_METHOD AM_RSA_DECRYPT =
  {&AIT_RSAPublic, 0, &KIT_RSAPublic, (POINTER)&A_RSA_CRYPT};
B_ALGORITHM_METHOD AM_RSA_ENCRYPT =
  {&AIT_RSAPublic, 1, &KIT_RSAPublic, (POINTER)&A_RSA_CRYPT};

static int RSAQuery (contextLen, key, params)
unsigned int *contextLen;
POINTER key;
POINTER params;
{
UNUSED_ARG (params)

  if (A_IntegerBits
      (((A_RSA_KEY *)key)->modulus.data, ((A_RSA_KEY *)key)->modulus.len)
      > MAX_RSA_MODULUS_BITS)
    /* Key size is too big to handle. */
    return (AE_MODULUS_LEN);

  *contextLen = sizeof (A_RSA_CTX);
  return (0);
}

static int RSAInit (context, key, params, surrenderContext)
POINTER context;
POINTER key;
POINTER params;
A_SURRENDER_CTX *surrenderContext;
{
UNUSED_ARG (params)
UNUSED_ARG (surrenderContext)

  return (A_RSAInit ((A_RSA_CTX *)context, (A_RSA_KEY *)key));
}

static int RSAUpdate
  (context, output, outputLen, maxOutputLen, input, inputLen, surrenderContext)
POINTER context;
unsigned char *output;
unsigned int *outputLen;
unsigned int maxOutputLen;
const unsigned char *input;
unsigned int inputLen;
A_SURRENDER_CTX *surrenderContext;
{
  return (A_RSAUpdate
          ((A_RSA_CTX *)context, output, outputLen, maxOutputLen, input,
           inputLen, surrenderContext));
}

static int RSAFinal
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
  return (A_RSAFinal ((A_RSA_CTX *)context));
}

static int RSAGetMaxOutputLen (context, outputLen, inputLen)
POINTER context;
unsigned int *outputLen;
unsigned int inputLen;
{
  *outputLen = A_RSA_MAX_OUTPUT_LEN ((A_RSA_CTX *)context, inputLen);
  return (0);
}

static int RSAGetBlockLen (context, blockLen)
POINTER context;
unsigned int *blockLen;
{
  *blockLen = A_RSA_BLOCK_LEN ((A_RSA_CTX *)context);
  return(0);
}
