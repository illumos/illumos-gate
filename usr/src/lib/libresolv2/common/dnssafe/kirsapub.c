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
#include "kirsapub.h"
#include "port_after.h"

B_KeyInfoType KIT_RSAPublic =
  {KIT_RSAPublicAddInfo, KIT_RSAPublicMakeInfo};

static A_RSA_KEY STATIC_RSA_KEY;
static ITEM *RSA_KEY_ITEMS[] =
  {&STATIC_RSA_KEY.modulus, &STATIC_RSA_KEY.exponent};

int KI_RSAPublic (keyInfoType)
POINTER *keyInfoType;
{
  *keyInfoType = (POINTER)&KIT_RSAPublic;

  /* Return 1 to indicate a KeyInfoType, not an AlgorithmInfoType */
  return (1);
}

int KIT_RSAPublicAddInfo (key, info)
B_Key *key;
POINTER info;
{
  POINTER newValue;
  int status;
  
  /* Allocate memory for A_RSA_KEY struct and copy integers
       from supplied value.
     */
  if ((status = B_MemoryPoolAlloc
       (&key->infoCache.memoryPool, &newValue, sizeof (A_RSA_KEY))) != 0)
    return (status);
  if ((status = AllocAndCopyIntegerItems
       (newValue, info, (POINTER)&STATIC_RSA_KEY, RSA_KEY_ITEMS,
        sizeof (RSA_KEY_ITEMS) / sizeof (RSA_KEY_ITEMS[0]),
        &key->infoCache.memoryPool)) != 0)
    return (status);
    
  return (B_InfoCacheAddInfo
          (&key->infoCache, (POINTER)&KIT_RSAPublic, newValue));
}

int KIT_RSAPublicMakeInfo (info, key)
POINTER *info;
B_Key *key;
{
  A_RSA_KEY keyValue;
  int status;
  
  /* If not already found in the cache, try to get values from
       a full private key info, setting unneeded entries to NULL.
   */
  if ((status = GetFullPrivateKeyInfo
       (&keyValue.modulus, &keyValue.exponent, (ITEM *)NULL_PTR,
        (ITEM *)NULL_PTR, (ITEM *)NULL_PTR, (ITEM *)NULL_PTR, key)) != 0)
    return (status);

  /* Got all the needed fields, so allocate memory for a new
       A_RSA_KEY struct and copy the key value.
   */
  if ((status = B_MemoryPoolAlloc
       (&key->infoCache.memoryPool, info, sizeof (A_RSA_KEY))) != 0)
    return (status);
    
  **(A_RSA_KEY **)info = keyValue;
  return (0);
}
