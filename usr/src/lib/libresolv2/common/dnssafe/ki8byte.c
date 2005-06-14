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
#include "kiitem.h"
#include "ki8byte.h"
#include "port_after.h"

int KIT_8ByteAddInfo PROTO_LIST ((B_Key *, POINTER));
int KIT_8ByteMakeInfo PROTO_LIST ((POINTER *, B_Key *));

B_KeyInfoType KIT_8Byte = {KIT_8ByteAddInfo, KIT_8ByteMakeInfo};

int KI_8Byte (keyInfoType)
POINTER *keyInfoType;
{
  *keyInfoType = (POINTER)&KIT_8Byte;

  /* Return 1 to indicate a KeyInfoType, not an AlgorithmInfoType */
  return (1);
}

/* info points to 8 byte key.
   Cache as a KITItem and a KIT_8Byte.
 */
int KIT_8ByteAddInfo (key, info)
B_Key *key;
POINTER info;
{
  POINTER newData;
  int status;
  
  /* Copy the 8 byte key. */
  if ((status = B_MemoryPoolAllocAndCopy
       (&key->infoCache.memoryPool, &newData, info, 8)) != 0)
    return (status);

  /* Cache as a KITItem as well as KIT_8Byte.
   */
  if ((status = B_KeyAddItemInfo (key, (unsigned char *)newData, 8)) != 0)
    return (status);
  return (B_InfoCacheAddInfo (&key->infoCache, (POINTER)&KIT_8Byte, newData));
}

int KIT_8ByteMakeInfo (info, key)
POINTER *info;
B_Key *key;
{
  ITEM *item;
  int status;
  
  /* Try to make one from a KI_Item.  Since KI_Item doesn't
       call KI_8Byte, this should not cause an endless loop.
   */
  if ((status = B_KeyGetInfo (key, (POINTER *)&item, &KITItem)) != 0)
    return (status);
  if (item->len != 8)
    return (BE_WRONG_KEY_INFO);

  *(unsigned char **)info = item->data;
  return (0);
}

