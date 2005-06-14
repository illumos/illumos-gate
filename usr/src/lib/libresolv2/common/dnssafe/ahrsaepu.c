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
#include "ahrsaepu.h"
#include "port_after.h"

static int EncodeBlock2 PROTO_LIST
  ((AH_RSAEncryptionPublic *, B_Algorithm *, A_SURRENDER_CTX *));
static int DecodeBlock1 PROTO_LIST
  ((AH_RSAEncryptionPublic *, ITEM *, unsigned int));

static AH_RSAEncryptionVTable ENCRYPTION_V_TABLE =
  {EncodeBlock2, DecodeBlock1};

extern struct B_AlgorithmInfoType AIT_RSAPublic;

AH_RSAEncryptionPublic *AH_RSAEncrypPublicConstructor (handler)
AH_RSAEncryptionPublic *handler;
{
  if (handler == (AH_RSAEncryptionPublic *)NULL_PTR) {
    /* This constructor is being used to do a new */
    if ((handler = (AH_RSAEncryptionPublic *)T_malloc (sizeof (*handler)))
        == (AH_RSAEncryptionPublic *)NULL_PTR)
      return (handler);
  }

  /* Construct base class */
  AH_RSAEncryptionConstructor1 (handler, &AIT_RSAPublic);
  
  handler->vTable = &ENCRYPTION_V_TABLE;
  return (handler);
}

/* block starts out with the input bytes of length inputLen left-justified.
 */
static int EncodeBlock2 (handler, randomAlgorithm, surrenderContext)
AH_RSAEncryptionPublic *handler;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;
  unsigned char randomByte;
  unsigned int padLen, i;

  if ((handler->_inputLen + 3) > handler->z.blockLen)
    /* input is too large to make a block 2 */
    return (BE_INPUT_LEN);

  padLen = handler->z.blockLen - (handler->_inputLen + 3);
  T_memmove
    ((POINTER)(handler->z.block + padLen + 3), (POINTER)handler->z.block,
     handler->_inputLen);

  handler->z.block[0] = 0;
  handler->z.block[1] = 2;

  /* Pad out with random bytes, making sure that none of the bytes is zero.
   */
  for (i = 2; i < (padLen + 2); i++) {
    do {
      if ((status = B_AlgorithmGenerateRandomBytes
           (randomAlgorithm, &randomByte, 1, surrenderContext)) != 0)
        return (status);
    } while (randomByte == 0);
    
    handler->z.block[i] = randomByte;
  }
  
  handler->z.block[2 + padLen] = 0;
  return (0);
}

static int DecodeBlock1 (handler, output, block1Len)
AH_RSAEncryptionPublic *handler;
ITEM *output;
unsigned int block1Len;
{
  unsigned int i;
  
  /* Locate the digestInfo within the PKCS block 1.
   */
  if (handler->z.block[0] != 0 || handler->z.block[1] != 1)
    return (BE_INPUT_DATA);
    
  /* Should be able to find the data after the first zero byte following
       the 0xff. */
  for (i = 2; i < block1Len && handler->z.block[i] == 0xff; i++);
  i++;
    
  if (i > block1Len || handler->z.block[i - 1] != 0)
    /* The data is not zero terminated, or a byte other than 0xff. */
    return (BE_INPUT_DATA);

  output->len = block1Len - i;
  output->data = handler->z.block + i;
  return (0);
}

