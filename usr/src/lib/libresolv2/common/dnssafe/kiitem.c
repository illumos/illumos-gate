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
#include "port_after.h"

int KITItemAddInfo PROTO_LIST ((B_Key *, POINTER));

B_KeyInfoType KITItem = {KITItemAddInfo, B_KeyInfoTypeMakeError};

int KI_Item (keyInfoType)
POINTER *keyInfoType;
{
  *keyInfoType = (POINTER)&KITItem;

  /* Return 1 to indicate a KeyInfoType, not an AlgorithmInfoType */
  return (1);
}

/* info is an ITEM.  The ITEM's data is copied into the object.
 */
int KITItemAddInfo (key, info)
B_Key *key;
POINTER info;
{
  unsigned char *newData;
  int status;
  
  if ((status = B_MemoryPoolAllocAndCopy
       (&key->infoCache.memoryPool, (POINTER *)&newData,
        (POINTER)((ITEM *)info)->data, ((ITEM *)info)->len)) != 0)
    return (status);
    
  return (B_KeyAddItemInfo (key, newData, ((ITEM *)info)->len));
}

