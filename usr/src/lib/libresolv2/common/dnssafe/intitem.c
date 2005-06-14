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
#include "bmempool.h"
#include "intitem.h"
#include "port_after.h"

/* Copy itemCount ITEMs from source to destination, allocating new
     memory in the memoryPool.
   Each ITEM is a canonical integer, and is stripped of leading zeros.
   Use the list of staticItems as a template.  Each of the staticItems
     points to the ITEM within the staticStruct, which is a structure
     of the same format as destination and source.
   Returns 0, BE_ALLOC.
 */
int AllocAndCopyIntegerItems
  (destination, source, staticStruct, staticItems, itemCount, memoryPool)
POINTER destination;
POINTER source;
POINTER staticStruct;
ITEM **staticItems;
unsigned int itemCount;
B_MemoryPool *memoryPool;
{
  ITEM sourceItem, *destinationItem;
  int status;
  unsigned int i, offset;
  
  for (i = 0; i < itemCount; i++) {
    offset = (unsigned int)((char *)staticItems[i] - (char *)staticStruct);
    sourceItem = *(ITEM *)((char *)source + offset);
    destinationItem = (ITEM *)((char *)destination + offset);

    while (sourceItem.len > 0 && *sourceItem.data == 0) {
      sourceItem.len--;
      sourceItem.data++;
    }
    
    if ((status = B_MemoryPoolAllocAndCopy
         (memoryPool, (POINTER *)&destinationItem->data,
          (POINTER)sourceItem.data, destinationItem->len = sourceItem.len))
        != 0)
      return (status);
  }
  
  return (0);
}

