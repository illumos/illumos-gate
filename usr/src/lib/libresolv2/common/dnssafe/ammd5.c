/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) RSA Data Security, Inc. created 1990, 1996.  This is an
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
#include "md5.h"
#include "amdigest.h"
#include "port_after.h"

static int amMD5Query PROTO_LIST ((unsigned int *, POINTER));
static int amMD5Init PROTO_LIST ((POINTER, POINTER, A_SURRENDER_CTX*));
static int amMD5Update PROTO_LIST
  ((POINTER, const unsigned char *, unsigned int, A_SURRENDER_CTX*));
static int amMD5Final PROTO_LIST
  ((POINTER, unsigned char *, unsigned int *, unsigned int, A_SURRENDER_CTX*));
static int amMD5GetMaxOutputLen PROTO_LIST ((POINTER, unsigned int *));

static A_DIGEST_ALGA A_MD5_DIGEST = {
  amMD5Query, amMD5Init, amMD5Update, amMD5Final, amMD5GetMaxOutputLen
};

extern struct B_AlgorithmInfoType AIT_MD5;

B_ALGORITHM_METHOD AM_MD5 =
  {&AIT_MD5, 0, (struct B_KeyInfoType *)NULL_PTR, (POINTER)&A_MD5_DIGEST};

/* Returns 0.
 */
static int amMD5Query (contextLen, params)
unsigned int *contextLen;
POINTER params;
{
UNUSED_ARG (params)

  *contextLen = sizeof (A_MD5_CTX);
  return (0);
}

/* Returns 0.
 */
static int amMD5Init (context, params, surrenderContext)
POINTER context;
POINTER params;
A_SURRENDER_CTX *surrenderContext;
{
UNUSED_ARG (params)
UNUSED_ARG (surrenderContext)

  A_MD5Init ((A_MD5_CTX *)context);
  return (0);
}

/* Returns 0.
 */
static int amMD5Update (context, input, inputLen, surrenderContext)
POINTER context;
const unsigned char *input;
unsigned int inputLen;
A_SURRENDER_CTX *surrenderContext;
{
UNUSED_ARG (surrenderContext)

  A_MD5Update ((A_MD5_CTX *)context, input, inputLen);
  return (0);
}

/* Returns 0, AE_OUTPUT_LEN if maxDigestLen is too small.
 */
static int amMD5Final
  (context, digest, digestLen, maxDigestLen, surrenderContext)
POINTER context;
unsigned char *digest;
unsigned int *digestLen;
unsigned int maxDigestLen;
A_SURRENDER_CTX *surrenderContext;
{
UNUSED_ARG (surrenderContext)

  if ((*digestLen = A_MD5_DIGEST_LEN) > maxDigestLen)
    return (AE_OUTPUT_LEN);

  A_MD5Final ((A_MD5_CTX *)context, digest);
  return (0);
}

static int amMD5GetMaxOutputLen (context, outputLen)
POINTER context;
unsigned int *outputLen;
{
UNUSED_ARG (context)

  *outputLen = A_MD5_DIGEST_LEN;
  return(0);
}
