/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
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
#include "md5rand.h"
#include "amrandom.h"
#include "port_after.h"

static int MD5RandomQuery PROTO_LIST ((unsigned int *, POINTER));
static int MD5RandomInit PROTO_LIST ((POINTER, POINTER, A_SURRENDER_CTX *));
static int MD5RandomUpdate PROTO_LIST
  ((POINTER, unsigned char *, unsigned int, A_SURRENDER_CTX *));
static int MD5RandomGenerateBytes PROTO_LIST
  ((POINTER, unsigned char *, unsigned int, A_SURRENDER_CTX *));

extern struct B_AlgorithmInfoType AIT_MD5Random;

static A_RANDOM_ALGA A_MD5_RANDOM =
  {MD5RandomQuery, MD5RandomInit, MD5RandomUpdate, MD5RandomGenerateBytes};

B_ALGORITHM_METHOD AM_MD5_RANDOM =
  {&AIT_MD5Random, 0, (struct B_KeyInfoType *)NULL_PTR,
   (POINTER)&A_MD5_RANDOM};

static int MD5RandomQuery (contextLen, params)
unsigned int *contextLen;
POINTER params;
{
UNUSED_ARG (params)

  *contextLen = sizeof (A_MD5_RANDOM_CTX);
  return (0);
}

static int MD5RandomInit (context, params, surrenderContext)
POINTER context;
POINTER params;
A_SURRENDER_CTX *surrenderContext;
{
UNUSED_ARG (params)
UNUSED_ARG (surrenderContext)

  A_MD5RandomInit ((A_MD5_RANDOM_CTX *)context);
  return (0);
}

static int MD5RandomUpdate (context, input, inputLen, surrenderContext)
POINTER context;
unsigned char *input;
unsigned int inputLen;
A_SURRENDER_CTX *surrenderContext;
{
UNUSED_ARG (surrenderContext)

  A_MD5RandomUpdate ((A_MD5_RANDOM_CTX *)context, input, inputLen);
  return (0);
}

static int MD5RandomGenerateBytes
  (context, output, outputLen, surrenderContext)
POINTER context;
unsigned char *output;
unsigned int outputLen;
A_SURRENDER_CTX *surrenderContext;
{
UNUSED_ARG (surrenderContext)

  A_MD5RandomGenerateBytes ((A_MD5_RANDOM_CTX *)context, output, outputLen);
  return (0);
}
