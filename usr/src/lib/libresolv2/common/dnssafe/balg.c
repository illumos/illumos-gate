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
#include "bkey.h"
#include "balg.h"
#include "btypechk.h"
#include "ainfotyp.h"
#include "port_after.h"

void B_AlgorithmConstructor (algorithm)
B_Algorithm *algorithm;
{
  /* Construct immediate base class. */
  B_InfoCacheConstructor (&algorithm->infoCache);

  T_memset ((POINTER)&algorithm->z, 0, sizeof (algorithm->z));
}

void B_AlgorithmDestructor (algorithm)
B_Algorithm *algorithm;
{
  if (algorithm->z.handler != (B_TypeCheck *)NULL_PTR) {
    B_TYPE_CHECK_Destructor (algorithm->z.handler);
    T_free ((POINTER)algorithm->z.handler);
  }

  /* Destroy base class */
  B_INFO_CACHE_Destructor (&algorithm->infoCache);
}

int B_AlgorithmCheckType (algorithm, Destructor)
B_Algorithm *algorithm;
B_TYPE_CHECK_DESTRUCTOR Destructor;
{
  if (algorithm->z.handler == (B_TypeCheck *)NULL_PTR)
    return (BE_ALGORITHM_NOT_SET);

  if (algorithm->z.handler->_Destructor != Destructor)
    return (BE_ALG_OPERATION_UNKNOWN);

  return (0);
}

int B_AlgorithmCheckTypeAndInitFlag (algorithm, Destructor)
B_Algorithm *algorithm;
B_TYPE_CHECK_DESTRUCTOR Destructor;
{
  int status;

  /* Check the type first. */
  if ((status = B_AlgorithmCheckType (algorithm, Destructor)) != 0)
    return (status);

  if (!algorithm->z.initFlag)
    return (BE_ALGORITHM_NOT_INITIALIZED);

  return (0);
}

int B_AlgorithmSetInfo (algorithm, algorithmInfoType, info)
B_Algorithm *algorithm;
B_AlgorithmInfoType *algorithmInfoType;
POINTER info;
{
  int status;
  
  if (algorithm->infoCache.z.infoCount > 0)
    return (BE_ALGORITHM_ALREADY_SET);

  /* This will cache the encoding. */
  if ((status = (*algorithmInfoType->vTable->AddInfo)
       (algorithmInfoType, algorithm, info)) != 0)
    return (status);

  /* Allocate the algorithm handler.  NewHandler returns NULL_PTR for error.
   */
  if ((algorithm->z.handler = (*algorithmInfoType->vTable->NewHandler)
       (algorithmInfoType, algorithm)) == (B_TypeCheck *)NULL_PTR)
    return (BE_ALLOC);

  return (0);
}

int B_AlgorithmGetInfo (algorithm, info, algorithmInfoType)
B_Algorithm *algorithm;
POINTER *info;
B_AlgorithmInfoType *algorithmInfoType;
{
  int status;
  
  if (algorithm->infoCache.z.infoCount == 0)
    return (BE_ALGORITHM_NOT_SET);

  /* First check if the encoding is already in the encoding cache.
   */
  if (B_InfoCacheFindInfo
      (&algorithm->infoCache, info, (POINTER)algorithmInfoType) == 0)
    return (0);
  
  /* Info is not in the cache, go ahead and encode.
   */
  if ((status = (*algorithmInfoType->vTable->MakeInfo)
       (algorithmInfoType, info, algorithm)) != 0)
    return (status);

  return (B_InfoCacheAddInfo
          (&algorithm->infoCache, (POINTER)algorithmInfoType, *info));
}

