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
#include "bmempool.h"
#include "port_after.h"

#define ALLOCED_LIST_SLACK 10

void B_MemoryPoolConstructor (memoryPool)
B_MemoryPool *memoryPool;
{
  T_memset ((POINTER)&memoryPool->z, 0, sizeof (memoryPool->z));
} 

void B_MemoryPoolDestructor (memoryPool)
B_MemoryPool *memoryPool;
{
  B_MemoryPoolReset (memoryPool);
  T_free ((POINTER)memoryPool->z.allocedList);
}

/* For each item on the alloced list, call the DeleteFuncion if
     there is one, otherwise zerioze and free.
   Leave the list itself allocated with all NULL entries.
 */
void B_MemoryPoolReset (memoryPool)
B_MemoryPool *memoryPool;
{
  B_ALLOCED_DATA *allocedData;
  unsigned int i;

  for (i = memoryPool->z.allocedCount,
       allocedData = memoryPool->z.allocedList;
       i-- > 0;
       ++allocedData) {
    /* Only process this entry if the data is not NULL_PTR.
     */
    if (allocedData->object != NULL_PTR) {
      if (allocedData->DeleteFunction != NULL)
        /* There is a destroy function, so call. */
        (*allocedData->DeleteFunction) (allocedData->object);
      else {
        T_memset (allocedData->object, 0, allocedData->size);
        T_free (allocedData->object);
      }
      allocedData->object = NULL_PTR;
    }
  }

  memoryPool->z.allocedCount = 0;
  /* Note that maxAllocedCount still indicates the size of the alloced list. */
}

/* On any error return, NULL_PTR is returned for the data.
   Returns 0 if successful, or BE_ALLOC if cannot alloc the memory.
 */
int B_MemoryPoolAlloc (memoryPool, data, size)
B_MemoryPool *memoryPool;
POINTER *data;
unsigned int size;
{
  if ((*data = T_malloc (size)) == NULL_PTR)
    return (BE_ALLOC);
  return (B_MemoryPoolAdoptData (memoryPool, data, size));
}

/* Use alloc to allocate the newData of length size and T_memcpy data into it.
   On any error return, NULL_PTR is returned for the newData.
   Returns 0 if successful or BE_ALLOC if cannot alloc the memory.
 */
int B_MemoryPoolAllocAndCopy (memoryPool, newData, data, size)
B_MemoryPool *memoryPool;
POINTER *newData;
POINTER data;
unsigned int size;
{
  int status;
  
  if ((status = B_MemoryPoolAlloc (memoryPool, newData, size)) != 0)
    return (status);
  
  T_memcpy (*newData, data, size);
  return (0);
}

/* Put the given data on the memory pool's alloced list.
   The size of the alloced data buffer must be passed in so that it can
     be zeroized when the object is reset (Pass in a size of zero if
     the buffer does not need to be zeroized.)
   The data is passed by reference, so that if there is an error,
     the data is zeroized and freed, and the pointer to the data is set
     to NULL_PTR.
   This routine should be used with caution - it is meant be called
     immediately after an alloc.
   No check is made as to whether the data is already on the memory pool's 
     alloced list (which would be a problem since it will get freed twice).
   Returns 0 if successful or BE_ALLOC if cannot expand the alloced list.
 */       
int B_MemoryPoolAdoptData (memoryPool, data, size)
B_MemoryPool *memoryPool;
POINTER *data;
unsigned int size;
{
  int status;
  
  if ((status = B_MemoryPoolAdoptHelper(memoryPool, *data, size, NULL)) != 0) {
    T_memset (*data, 0, size);
    T_free (*data);
    *data = NULL_PTR;
    return (status);
  }

  return (0);
}

/* Put the given object on the memory pool's alloced list.
   The size of the alloced object must be passed in so that it can
     be zeroized when the object is reset (Pass in a size of zero if
     the buffer does not need to be zeroized, especially if it
     is an object and not a data buffer.)
   The object is not passed by reference.  If there is an error,
     the calling routine should clean up the object, such as zeroizing
     and freeing.
   No check is made as to whether the object is already on the memory pool's 
     alloced list (which would be a problem since it will get freed twice).
   Returns 0 if successful or BE_ALLOC if cannot expand the alloced list.
 */       
int B_MemoryPoolAdoptHelper (memoryPool, object, size, DeleteFunction)
B_MemoryPool *memoryPool;
POINTER object;
unsigned int size;
B_MEMORY_POOL_DELETE_FUNCTION DeleteFunction;
{
  POINTER newList;
  unsigned int newMaxCount;

  if (memoryPool->z.allocedCount + 1 > memoryPool->z.maxAllocedCount) {
    /* Make extra room on the alloced list.
     */
    newMaxCount = memoryPool->z.allocedCount + ALLOCED_LIST_SLACK;
    if ((newList = T_malloc (newMaxCount * sizeof (B_ALLOCED_DATA)))
        == NULL_PTR)
      /* alloc errorm so caller should clean up the object it passed. */
      return (BE_ALLOC);
    
    /* move in new list and free old list */
    T_memcpy
      (newList, (POINTER)memoryPool->z.allocedList,
       memoryPool->z.allocedCount * sizeof (B_ALLOCED_DATA));
    T_free ((POINTER)memoryPool->z.allocedList);
    memoryPool->z.allocedList = (B_ALLOCED_DATA *)newList;
    memoryPool->z.maxAllocedCount = newMaxCount;
  }
  
  /* Put object on alloced list and increment count.
   */
  memoryPool->z.allocedList[memoryPool->z.allocedCount].object = object;
  memoryPool->z.allocedList[memoryPool->z.allocedCount].size = size;
  memoryPool->z.allocedList[memoryPool->z.allocedCount++].DeleteFunction =
    DeleteFunction;
  return (0);
}

/* 'data' points to the pointer to realloc and also is used to
     return the realloced memory.
   If data points to NULL_PTR, behaves like B_MemoryPoolAlloc.
   Find 'data' on the allocedList and realloc it to the given size,
     replacing the entry on the alloced list with the new memory.
   If it is not on the allocedList, the adopt the reallocated memory.
   If the buffer must be moved during the realloc, the old buffer is not
     zeroized (unless T_realloc does the zeroizing).
   This assumes that the (POINTER *)data is not (POINTER *)NULL_PTR.
   This assumes there is no DesroyFunction for this entry.  That is,
     you should not try to resize an object.
   On any error return, NULL_PTR is returned for the data.
   Returns 0 if successful or BE_ALLOC if cannot alloc the memory.
 */
int B_MemoryPoolRealloc (memoryPool, data, size)
B_MemoryPool *memoryPool;
POINTER *data;
unsigned int size;
{
  B_ALLOCED_DATA *allocedData;

  allocedData = B_MemoryPoolFindAllocedObject (memoryPool, *data);

  if ((*data = T_realloc (*data, size)) == NULL_PTR) {
    if (allocedData != (B_ALLOCED_DATA *)NULL_PTR)
      /* Could not reallocate, so nullify this entry. */
      allocedData->object = NULL_PTR;

    return (BE_ALLOC);
  }
  
  /* Realloc was successful.
   */
  if (allocedData == (B_ALLOCED_DATA *)NULL_PTR)
    /* The data was not in the memory pool to start with, so adopt it.
       Note that this also happens when the data is initially NULL_PTR. */
    return (B_MemoryPoolAdoptData (memoryPool, data, size));
  
  /* Replace the entry on the alloced list with the new memory.
   */
  allocedData->object = *data;
  allocedData->size = size;
  return (0);
}

/* Find the object in the alloced list, call the DeleteFunction if
     there is one, zeroize it and free it, nullifying that alloced list entry.
   The object to be freed is passed by pointer and is set to NULL_PTR to
     enforce the fact that the address no longer points to valid memory.
   This assumes that the (POINTER *)data is not (POINTER *)NULL_PTR.
   If the address is not found on the alloced list, only set the address
     to NULL_PTR.
 */
void B_MemoryPoolFree (memoryPool, object)
B_MemoryPool *memoryPool;
POINTER *object;
{
  B_ALLOCED_DATA *allocedData;
  
  if ((allocedData = B_MemoryPoolFindAllocedObject (memoryPool, *object))
      != (B_ALLOCED_DATA *)NULL_PTR) {
    if (allocedData->DeleteFunction != NULL)
      /* There is a destroy function, so call. */
      (*allocedData->DeleteFunction) (allocedData->object);
    else {
      T_memset (*object, 0, allocedData->size);
      T_free (*object);
    }

    /* Set this entry to NULL_PTR so that reset will not process it. */
    allocedData->object = NULL_PTR;
  }
  
  *object = NULL_PTR;
}

/* Return a pointer to the alloced object entry in the memoryPool.
   Return (ALLOCED_DATA *)NULL_PTR if object is NULL_PTR or object is not
     in the memoryPool.
 */
B_ALLOCED_DATA *B_MemoryPoolFindAllocedObject (memoryPool, object)
B_MemoryPool *memoryPool;
POINTER object;
{
  B_ALLOCED_DATA *allocedData;
  unsigned int i;
  
  if (object == NULL_PTR)
    return ((B_ALLOCED_DATA *)NULL_PTR);
  
  for (i = memoryPool->z.allocedCount,
       allocedData = memoryPool->z.allocedList;
       i-- > 0;
       ++allocedData) {
    if (allocedData->object == object)
      return (allocedData);
  }

  /* data not found. */
  return ((B_ALLOCED_DATA *)NULL_PTR);
}

