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

/* Define this so that the type of the 'this' pointer in the
     virtual functions will be correct for this derived class.
 */
struct A_MD5_RANDOM_CTX;
#define THIS_DIGEST_RANDOM struct A_MD5_RANDOM_CTX

#include "port_before.h"
#include "global.h"
#include "algae.h"
#include "md5rand.h"
#include "port_after.h"

static void A_MD5RandomDigestUpdate PROTO_LIST
  ((A_MD5_RANDOM_CTX *, unsigned char *, unsigned int));
static void A_MD5RandomDigestFinal PROTO_LIST
  ((A_MD5_RANDOM_CTX *, unsigned char *));

static A_DigestRandomVTable V_TABLE =
  {A_MD5RandomDigestUpdate, A_MD5RandomDigestFinal};

void A_MD5RandomInit (context)
A_MD5_RANDOM_CTX *context;
{
  /* Initialize "base class" */
  A_DigestRandomInit
    (&context->digestRandom, A_MD5_DIGEST_LEN, context->state);

  /* Initialize digest algorithm and set vTable.
   */
  A_MD5Init (&context->md5Context);
  context->digestRandom.vTable = &V_TABLE;
}

void A_MD5RandomUpdate (context, input, inputLen)
A_MD5_RANDOM_CTX *context;
unsigned char *input;
unsigned int inputLen;
{
  A_DigestRandomUpdate (&context->digestRandom, input, inputLen);
}

void A_MD5RandomGenerateBytes (context, output, outputLen)
A_MD5_RANDOM_CTX *context;
unsigned char *output;
unsigned int outputLen;
{
  A_DigestRandomGenerateBytes (&context->digestRandom, output, outputLen);
}

static void A_MD5RandomDigestUpdate (context, input, inputLen)
A_MD5_RANDOM_CTX *context;
unsigned char *input;
unsigned int inputLen;
{
  A_MD5Update (&context->md5Context, input, inputLen);
}

static void A_MD5RandomDigestFinal (context, digest)
A_MD5_RANDOM_CTX *context;
unsigned char *digest;
{
  A_MD5Final (&context->md5Context, digest);
}
