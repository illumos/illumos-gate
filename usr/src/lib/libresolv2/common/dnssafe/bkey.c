/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) RSA Data Security, Inc. created 1993, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

#include "port_before.h"
#include "global.h"
#include "bsafe2.h"
#include "bkey.h"
#include "kinfotyp.h"
#include "kiitem.h"
#include "port_after.h"

int B_KeySetInfo (key, keyInfoType, info)
B_Key *key;
B_KeyInfoType *keyInfoType;
POINTER info;
{
  if (key == (B_Key *)NULL_PTR)
    return (BE_KEY_OBJ);

  if (key->infoCache.z.infoCount > 0)
    return (BE_KEY_ALREADY_SET);

  /* This will cache the encoding. */
  return ((*keyInfoType->AddInfo) (key, info));
}

int B_KeyGetInfo (key, info, keyInfoType)
B_Key *key;
POINTER *info;
B_KeyInfoType *keyInfoType;
{
  int status;
  
  if (key == (B_Key *)NULL_PTR)
    return (BE_KEY_OBJ);

  if (key->infoCache.z.infoCount == 0)
    return (BE_KEY_NOT_SET);

  /* First check if the encoding is already in the encoding cache.
   */
  if (B_InfoCacheFindInfo (&key->infoCache, info, (POINTER)keyInfoType) == 0)
    return (0);
  
  /* Info is not in the cache, go ahead and encode.
   */
  if ((status = (*keyInfoType->MakeInfo) (info, key)) != 0)
    return (status);

  return (B_InfoCacheAddInfo (&key->infoCache, (POINTER)keyInfoType, *info));
}

/* Create an ITEM out of the data and len and cache it as KITItem.
   The data is already alloced in the info cache.
   Returns 0, BE_ALLOC.
 */
int B_KeyAddItemInfo (key, data, len)
B_Key *key;
unsigned char *data;
unsigned int len;
{
  ITEM *newInfo;
  int status;
  
  if ((status = B_MemoryPoolAlloc
       (&key->infoCache.memoryPool, (POINTER *)&newInfo, sizeof (*newInfo)))
      != 0)
    return (status);
  
  newInfo->data = data;
  newInfo->len = len;
  
  return (B_InfoCacheAddInfo
          (&key->infoCache, (POINTER)&KITItem, (POINTER)newInfo));
}

/* Return the number of bits in the canonical, positive integer.
   B_IntegerBits (0) = 0.
 */
unsigned int B_IntegerBits (integer, integerLen)
unsigned char *integer;
unsigned int integerLen;
{
  unsigned char mask, byte;
  unsigned int bytes, bits;
  
  for (bytes = 0; bytes < integerLen && integer[bytes] == 0; bytes++);
  if (bytes == integerLen)
    return (0);
  
  /* Get byte to test and increment byte count for final calculation */
  byte = integer[bytes++];
  
  /* Get number of bits in most significant byte */
  for (bits = 8, mask = 0x80; (byte & mask) == 0; bits--, mask >>= 1);
  return (8 * (integerLen - bytes) + bits);
}

