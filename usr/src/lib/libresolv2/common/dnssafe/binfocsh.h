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

#ifndef _BINFOCSH_H_
#define _BINFOCSH_H_ 1

#include "bmempool.h"

typedef struct B_InfoCache {
  B_MemoryPool memoryPool;                                      /* inherited */
  struct {
    unsigned int infoCount;
    struct {
      POINTER infoType;
      POINTER info;
    } *infos;
    /* POINTER reserved; */
  } z;           /* z gives the members that are zeroized by the constructor */
} B_InfoCache;

void B_InfoCacheConstructor PROTO_LIST ((B_InfoCache *));
#define B_INFO_CACHE_Destructor(infoCache) \
  B_MemoryPoolDestructor (&(infoCache)->memoryPool)

int B_InfoCacheAddInfo PROTO_LIST ((B_InfoCache *, POINTER, POINTER));
int B_InfoCacheFindInfo PROTO_LIST ((B_InfoCache *, POINTER *, POINTER));

#endif
