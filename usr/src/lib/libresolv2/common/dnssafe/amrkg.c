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

#include "port_before.h"
#include "global.h"
#include "bsafe2.h"
#include "algae.h"
#include "rsakeygn.h"
#include "balgmeth.h"
#include "amgen.h"
#include "port_after.h"

#define THE_GEN_PARAMS ((A_RSA_KEY_GEN_PARAMS *)params)

extern struct B_AlgorithmInfoType AIT_RSAKeyGen;
extern struct B_KeyInfoType KIT_PKCS_RSAPrivate;

static int RSAKeyGenQuery PROTO_LIST
  ((unsigned int *, unsigned int *, unsigned int *, struct B_KeyInfoType **,
    POINTER));
static int RSAKeyGenInit PROTO_LIST
  ((POINTER, POINTER, POINTER, A_SURRENDER_CTX *));
static int RSAKeyGen PROTO_LIST
  ((POINTER, POINTER *, unsigned char *, A_SURRENDER_CTX *));

static A_GENERATE_ALGA A_RSA_KEY_GEN =
  {RSAKeyGenQuery, RSAKeyGenInit, RSAKeyGen};

B_ALGORITHM_METHOD AM_RSA_KEY_GEN =
  {&AIT_RSAKeyGen, 0, (struct B_KeyInfoType *)NULL_PTR,
   (POINTER)&A_RSA_KEY_GEN};

static int RSAKeyGenQuery
  (contextLen, secondContextLen, randomBlockLen, resultInfoType, params)
unsigned int *contextLen;
unsigned int *secondContextLen;
unsigned int *randomBlockLen;
struct B_KeyInfoType **resultInfoType;
POINTER params;
{
  if ((THE_GEN_PARAMS->modulusBits > MAX_RSA_MODULUS_BITS) ||
      (THE_GEN_PARAMS->modulusBits < MIN_RSA_MODULUS_BITS))
    /* Can't support a keypair of this size. */
    return (AE_MODULUS_LEN);
  
  *contextLen = sizeof (A_RSA_KEY_GEN_CTX);
  *secondContextLen = 0;
  *randomBlockLen =
     A_RSA_KEY_GEN_RANDOM_BLOCK_LEN (THE_GEN_PARAMS->modulusBits);
  *resultInfoType = &KIT_PKCS_RSAPrivate;

  return (0);
}

static int RSAKeyGenInit (context, secondContext, params, surrenderContext)
POINTER context;
POINTER secondContext;
POINTER params;
A_SURRENDER_CTX *surrenderContext;
{
UNUSED_ARG (secondContext)
UNUSED_ARG (surrenderContext)

  return (A_RSAKeyGenInit
          ((A_RSA_KEY_GEN_CTX *)context, (A_RSA_KEY_GEN_PARAMS *)params));
}

static int RSAKeyGen (context, result, randomBlock, surrenderContext)
POINTER context;
POINTER *result;
unsigned char *randomBlock;
A_SURRENDER_CTX *surrenderContext;
{
  return (A_RSAKeyGen
          ((A_RSA_KEY_GEN_CTX *)context, (A_PKCS_RSA_PRIVATE_KEY **)result,
           randomBlock, surrenderContext));
}

