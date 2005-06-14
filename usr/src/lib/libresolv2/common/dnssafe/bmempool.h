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

#ifndef _BMEMPOOL_H_
#define _BMEMPOOL_H_ 1

typedef void (*B_MEMORY_POOL_DELETE_FUNCTION) PROTO_LIST ((POINTER));

typedef struct {
  POINTER object;
  unsigned int size;
  B_MEMORY_POOL_DELETE_FUNCTION DeleteFunction;
} B_ALLOCED_DATA;

typedef struct {
  struct {
    unsigned int allocedCount;
    unsigned int maxAllocedCount;      /* Size of the actuall allocated list */
    B_ALLOCED_DATA *allocedList;
    /* POINTER reserved; */
  } z;           /* z gives the members that are zeroized by the constructor */
} B_MemoryPool;

void B_MemoryPoolConstructor PROTO_LIST ((B_MemoryPool *));
void B_MemoryPoolDestructor PROTO_LIST ((B_MemoryPool *));

void B_MemoryPoolReset PROTO_LIST ((B_MemoryPool *));
int B_MemoryPoolAlloc PROTO_LIST ((B_MemoryPool *, POINTER *, unsigned int));
int B_MemoryPoolAllocAndCopy PROTO_LIST
  ((B_MemoryPool *, POINTER *, POINTER, unsigned int));
int B_MemoryPoolAdoptData PROTO_LIST
  ((B_MemoryPool *, POINTER *, unsigned int));
int B_MemoryPoolAdoptObject PROTO_LIST
  ((B_MemoryPool *, POINTER *, B_MEMORY_POOL_DELETE_FUNCTION));
int B_MemoryPoolRealloc PROTO_LIST ((B_MemoryPool *, POINTER *, unsigned int));
int B_MemoryPoolSafeRealloc PROTO_LIST
  ((B_MemoryPool *, POINTER *, unsigned int));
void B_MemoryPoolFree PROTO_LIST ((B_MemoryPool *, POINTER *));
void B_MemoryPoolResetExceptObject PROTO_LIST ((B_MemoryPool *, POINTER));

/* These are "private member functions ".
 */
B_ALLOCED_DATA *B_MemoryPoolFindAllocedObject PROTO_LIST
  ((B_MemoryPool *, POINTER));
int B_MemoryPoolAdoptHelper PROTO_LIST
  ((B_MemoryPool *, POINTER, unsigned int, B_MEMORY_POOL_DELETE_FUNCTION));

#endif
