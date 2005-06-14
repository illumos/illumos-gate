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

/* Define this so that the type of the 'this' pointer in the
     virtual functions will be correct for this derived class.
 */
struct AH_RSAEncryption;
#define THIS_ENCRYPT_DECRYPT struct AH_RSAEncryption

#include "port_before.h"
#include "global.h"
#include "bsafe2.h"
#include "bkey.h"
#include "balg.h"
#include "ahrsaepr.h"
#include "port_after.h"

static int EncodeBlock1 PROTO_LIST
  ((AH_RSAEncryptionPrivate *, B_Algorithm *, A_SURRENDER_CTX *));
static int DecodeBlock2 PROTO_LIST
  ((AH_RSAEncryptionPrivate *, ITEM *, unsigned int));

static AH_RSAEncryptionVTable ENCRYPTION_V_TABLE =
  {EncodeBlock1, DecodeBlock2};

extern struct B_AlgorithmInfoType AIT_RSAPrivate;

AH_RSAEncryptionPrivate *AH_RSAEncrypPrivateConstructor (handler)
AH_RSAEncryptionPrivate *handler;
{
  if (handler == (AH_RSAEncryptionPrivate *)NULL_PTR) {
    /* This constructor is being used to do a new */
    if ((handler = (AH_RSAEncryptionPrivate *)T_malloc (sizeof (*handler)))
        == (AH_RSAEncryptionPrivate *)NULL_PTR)
      return (handler);
  }

  /* Construct base class */
  AH_RSAEncryptionConstructor1 (handler, &AIT_RSAPrivate);
  
  handler->vTable = &ENCRYPTION_V_TABLE;
  return (handler);
}

/* block1 starts out with the input bytes of length inputLen left-justified.
   Returns 0, BE_INPUT_LEN.
 */
static int EncodeBlock1 (handler, randomAlgorithm, surrenderContext)
AH_RSAEncryptionPrivate *handler;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  unsigned int padLen;

UNUSED_ARG (randomAlgorithm)
UNUSED_ARG (surrenderContext)
  if ((handler->_inputLen + 3) > handler->z.blockLen)
    /* input is too large to make a block 1 */
    return (BE_INPUT_LEN);

  padLen = handler->z.blockLen - (handler->_inputLen + 3);
  T_memmove
    ((POINTER)(handler->z.block + padLen + 3), (POINTER)handler->z.block,
     handler->_inputLen);

  handler->z.block[0] = 0;
  handler->z.block[1] = 1;
  T_memset ((POINTER)(handler->z.block + 2), 0xff, padLen);
  handler->z.block[2 + padLen] = 0;
  return (0);
}

static int DecodeBlock2 (handler, output, block2Len)
AH_RSAEncryptionPrivate *handler;
ITEM *output;
unsigned int block2Len;
{
  unsigned int i;
  
  if ((handler->z.block[0] != 0) || (handler->z.block[1] != 2))
    return (BE_INPUT_DATA);
    
  /* Should be able to find the data after the first zero byte following
       the random bytes. */
  for (i = 2; i < block2Len && handler->z.block[i] != 0; i++);
  i++;
    
  if (i > block2Len)
    /* The data is not zero terminated. */
    return (BE_INPUT_DATA);
    
  output->len = block2Len - i;
  output->data = handler->z.block + i;
  return (0);
}

