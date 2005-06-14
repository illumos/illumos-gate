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
#include "kipkcrpr.h"
#include "port_after.h"

B_KeyInfoType KIT_PKCS_RSAPrivate =
  {KIT_PKCS_RSAPrivateAddInfo, KIT_PKCS_RSAPrivateMakeInfo};

static A_PKCS_RSA_PRIVATE_KEY STATIC_PKCS_RSA_PRIVATE_KEY;
static ITEM *PKCS_RSA_PRIVATE_KEY_ITEMS[] = {
  &STATIC_PKCS_RSA_PRIVATE_KEY.modulus,
  &STATIC_PKCS_RSA_PRIVATE_KEY.publicExponent,
  &STATIC_PKCS_RSA_PRIVATE_KEY.privateExponent,
  &STATIC_PKCS_RSA_PRIVATE_KEY.prime[0],
  &STATIC_PKCS_RSA_PRIVATE_KEY.prime[1],
  &STATIC_PKCS_RSA_PRIVATE_KEY.primeExponent[0],
  &STATIC_PKCS_RSA_PRIVATE_KEY.primeExponent[1],
  &STATIC_PKCS_RSA_PRIVATE_KEY.coefficient
};

int KI_PKCS_RSAPrivate (keyInfoType)
POINTER *keyInfoType;
{
  *keyInfoType = (POINTER)&KIT_PKCS_RSAPrivate;

  /* Return 1 to indicate a KeyInfoType, not an AlgorithmInfoType */
  return (1);
}

int KIT_PKCS_RSAPrivateAddInfo (key, info)
B_Key *key;
POINTER info;
{
  A_PKCS_RSA_PRIVATE_KEY *newValue;
  int status;
  
  /* Allocate memory for A_PKCS_RSA_PRIVATE_KEY struct and copy integers
       from supplied value.
   */
  if ((status = B_MemoryPoolAlloc
       (&key->infoCache.memoryPool, (POINTER *)&newValue,
        sizeof (A_PKCS_RSA_PRIVATE_KEY))) != 0)
    return (status);
  if ((status = AllocAndCopyIntegerItems
       ((POINTER)newValue, info, (POINTER)&STATIC_PKCS_RSA_PRIVATE_KEY,
        PKCS_RSA_PRIVATE_KEY_ITEMS, sizeof (PKCS_RSA_PRIVATE_KEY_ITEMS) / 
        sizeof (PKCS_RSA_PRIVATE_KEY_ITEMS[0]), &key->infoCache.memoryPool))
      != 0)
    return (status);
    
  /* Cache the full private key info.
   */
  if ((status = CacheFullPrivateKey
       (key, &newValue->modulus, &newValue->publicExponent,
        &newValue->privateExponent, newValue->prime, newValue->primeExponent,
        &newValue->coefficient)) != 0)
    return (status);
  return (B_InfoCacheAddInfo
          (&key->infoCache, (POINTER)&KIT_PKCS_RSAPrivate, (POINTER)newValue));
}

int KIT_PKCS_RSAPrivateMakeInfo (info, key)
POINTER *info;
B_Key *key;
{
  A_PKCS_RSA_PRIVATE_KEY keyValue;
  int status;

  /* If not already found in the cache, try to get values from
     a full private key info.
   */
  if ((status = GetFullPrivateKeyInfo
       (&keyValue.modulus, &keyValue.publicExponent,
        &keyValue.privateExponent, keyValue.prime, keyValue.primeExponent,
        &keyValue.coefficient, key)) != 0)
    return (status);

  /* Got all the needed fields, so allocate memory for a new
     A_PKCS_RSA_PRIVATE_KEY struct and copy the key value.
   */
  if ((status = B_MemoryPoolAlloc
       (&key->infoCache.memoryPool, info, sizeof (A_PKCS_RSA_PRIVATE_KEY)))
      != 0)
    return (status);
    
  **(A_PKCS_RSA_PRIVATE_KEY **)info = keyValue;
  return (0);
}

