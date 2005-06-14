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
#include "bsafe2.h"
#include "bkey.h"
#include "kinfotyp.h"
#include "intitem.h"
#include "kifulprv.h"
#include "port_after.h"

#define NULL_UCHAR_PTR ((unsigned char *)NULL_PTR)

int KIT_RSA_CRTAddInfo PROTO_LIST ((B_Key *, POINTER));
int KIT_RSA_CRTMakeInfo PROTO_LIST ((POINTER *, B_Key *));

B_KeyInfoType KIT_RSA_CRT = {KIT_RSA_CRTAddInfo, KIT_RSA_CRTMakeInfo};

static A_RSA_CRT_KEY STATIC_RSA_CRT_KEY;
static ITEM *RSA_CRT_KEY_ITEMS[] = {
  &STATIC_RSA_CRT_KEY.modulus, &STATIC_RSA_CRT_KEY.prime[0],
  &STATIC_RSA_CRT_KEY.prime[1],
  &STATIC_RSA_CRT_KEY.primeExponent[0],
  &STATIC_RSA_CRT_KEY.primeExponent[1],
  &STATIC_RSA_CRT_KEY.coefficient
};

/* args points to A_RSA_CRT_KEY.
 */
int KI_RSA_CRT (keyInfoType)
POINTER *keyInfoType;
{
  *keyInfoType = (POINTER)&KIT_RSA_CRT;

  /* Return 1 to indicate a KeyInfoType, not an AlgorithmInfoType */
  return (1);
}

int KIT_RSA_CRTAddInfo (key, info)
B_Key *key;
POINTER info;
{
  A_RSA_CRT_KEY *newValue;
  int status;
  
  /* Allocate memory for A_RSA_CRT_KEY struct and copy integers
       from supplied value.
     */
  if ((status = B_MemoryPoolAlloc
       (&key->infoCache.memoryPool, (POINTER *)&newValue,
        sizeof (A_RSA_CRT_KEY))) != 0)
    return (status);
  if ((status = AllocAndCopyIntegerItems
       ((POINTER)newValue, info, (POINTER)&STATIC_RSA_CRT_KEY,
        RSA_CRT_KEY_ITEMS,
        sizeof (RSA_CRT_KEY_ITEMS) / sizeof (RSA_CRT_KEY_ITEMS[0]),
        &key->infoCache.memoryPool)) != 0)
    return (status);

  /* Cache the full private key info, setting unused fields to NULL.
   */
  if ((status = CacheFullPrivateKey
       (key, &newValue->modulus, (ITEM *)NULL_PTR, (ITEM *)NULL_PTR,
        newValue->prime, newValue->primeExponent, &newValue->coefficient))
      != 0)
    return (status);
  return (B_InfoCacheAddInfo
          (&key->infoCache, (POINTER)&KIT_RSA_CRT, (POINTER)newValue));
}

int KIT_RSA_CRTMakeInfo (info, key)
POINTER *info;
B_Key *key;
{
  A_RSA_CRT_KEY keyValue;
  int status;

  /* If not already found in the cache, try to get values from
       a full private key info, setting unneeded entries to NULL.
   */
  if ((status = GetFullPrivateKeyInfo
       (&keyValue.modulus, (ITEM *)NULL_PTR, (ITEM *)NULL_PTR,
        keyValue.prime, keyValue.primeExponent, &keyValue.coefficient,
        key)) != 0)
    return (status);

  /* Got all the needed fields, so allocate memory for a new
       A_RSA_CRT_KEY struct and copy the key value.
   */
  if ((status = B_MemoryPoolAlloc
       (&key->infoCache.memoryPool, info, sizeof (A_RSA_CRT_KEY))) != 0)
    return (status);
    
  **(A_RSA_CRT_KEY **)info = keyValue;
  return (0);
}

