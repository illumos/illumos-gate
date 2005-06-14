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
#include "binfocsh.h"
#include "port_after.h"

void B_InfoCacheConstructor (infoCache)
B_InfoCache *infoCache;
{
  /* Construct immediate base class. */
  B_MemoryPoolConstructor (&infoCache->memoryPool);

  T_memset ((POINTER)&infoCache->z, 0, sizeof (infoCache->z));
}

/* Returns 0, BE_ALLOC.
 */
int B_InfoCacheAddInfo (infoCache, infoType, info)
B_InfoCache *infoCache;
POINTER infoType;
POINTER info;
{
  int status;
  
  if ((status = B_MemoryPoolRealloc
       (&infoCache->memoryPool, (POINTER *)&infoCache->z.infos,
        (infoCache->z.infoCount + 1) * sizeof (infoCache->z.infos[0]))) != 0)
    return (status);
    
  infoCache->z.infos[infoCache->z.infoCount].infoType = infoType;
  infoCache->z.infos[infoCache->z.infoCount].info = info;
  infoCache->z.infoCount++;        
  
  return (0);
}

/* Set info to the entry in the cache for the given infoType.
   Returns 0, or BE_NOT_SUPPORTED if infoType is not in the cache.
 */
int B_InfoCacheFindInfo (infoCache, info, infoType)
B_InfoCache *infoCache;
POINTER *info;
POINTER infoType;
{
  unsigned int i;
  
  for (i = 0; i < infoCache->z.infoCount; ++i) {
    if (infoCache->z.infos[i].infoType == infoType) {
      /* The info has already been constructed. */
      *info = infoCache->z.infos[i].info;
      return (0);
    }
  }
  
  return (BE_NOT_SUPPORTED);
}

