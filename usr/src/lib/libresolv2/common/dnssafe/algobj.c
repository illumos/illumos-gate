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
#include "balg.h"
#include "ainfotyp.h"
#include "keyobj.h"
#include "algobj.h"
#include "port_after.h"

static char ALGORITHM_TYPE_TAG = 0;

int B_CreateAlgorithmObject (algorithmObject)
B_ALGORITHM_OBJ *algorithmObject;
{
  AlgorithmWrap *algorithmWrap;

  if ((*algorithmObject = T_malloc (sizeof (*algorithmWrap))) == NULL_PTR)
    return (BE_ALLOC);

  algorithmWrap = (AlgorithmWrap *)*algorithmObject;

  /* First construct base class */
  B_AlgorithmConstructor (&algorithmWrap->algorithm);
  
  algorithmWrap->typeTag = &ALGORITHM_TYPE_TAG;
  algorithmWrap->selfCheck = algorithmWrap;
  return (0);
}

void B_DestroyAlgorithmObject (algorithmObject)
B_ALGORITHM_OBJ *algorithmObject;
{
  AlgorithmWrap *algorithmWrap = (AlgorithmWrap *)*algorithmObject;

  if (AlgorithmWrapCheck (algorithmWrap) == 0) {
    /* zeroize self check to invalidate memory. */
    algorithmWrap->selfCheck = (AlgorithmWrap *)NULL_PTR;

    /* Call base class descructor */
    B_AlgorithmDestructor (&algorithmWrap->algorithm);

    T_free ((POINTER)algorithmWrap);
  }

  *algorithmObject = NULL_PTR;
}

int B_SetAlgorithmInfo (algorithmObject, infoType, info)
B_ALGORITHM_OBJ algorithmObject;
B_INFO_TYPE infoType;
POINTER info;
{
  B_AlgorithmInfoType *algorithmInfoType;
  int status;
  
  if ((status = AlgorithmWrapCheck (THE_ALG_WRAP)) != 0)
    return (status);

  /* Get the AlgorithmInfoType from the B_INFO_TYPE, which returns
       zero for an AlgorithmInfoType, non-zero for KeyInfoType
   */
  if ((*infoType) ((POINTER *)&algorithmInfoType) != 0)
    return (BE_KEY_OPERATION_UNKNOWN);
  
  return (B_AlgorithmSetInfo
          (&THE_ALG_WRAP->algorithm, algorithmInfoType, info));
}

int B_GetAlgorithmInfo (info, algorithmObject, infoType)
POINTER *info;
B_ALGORITHM_OBJ algorithmObject;
B_INFO_TYPE infoType;
{
  B_AlgorithmInfoType *algorithmInfoType;
  int status;
  
  if ((status = AlgorithmWrapCheck (THE_ALG_WRAP)) != 0)
    return (status);

  /* Get the AlgorithmInfoType from the B_INFO_TYPE, which returns
       zero for an AlgorithmInfoType, non-zero for KeyInfoType
   */
  if ((*infoType) ((POINTER *)&algorithmInfoType) != 0)
    return (BE_KEY_OPERATION_UNKNOWN);
  
  return (B_AlgorithmGetInfo
          (&THE_ALG_WRAP->algorithm, info, algorithmInfoType));
}

/* Return 0 if this is a valid AlgorithmWrap object. Return BE_ALGORITHM_OBJ if
     algorithmWrap is NULL_PTR or invalid.
 */
int AlgorithmWrapCheck (algorithmWrap)
AlgorithmWrap *algorithmWrap;
{
  return ((algorithmWrap != (AlgorithmWrap *)NULL_PTR &&
           algorithmWrap->selfCheck == algorithmWrap &&
           algorithmWrap->typeTag == &ALGORITHM_TYPE_TAG) ?
          0 : BE_ALGORITHM_OBJ);
}

/* Like AlgorithmWrapCheck except returns BE_RANDOM_OBJ for error.
   Also, return OK status if randomAlgorithm is NULL_PTR.
 */
int RandomAlgorithmCheck (randomAlgorithm)
B_ALGORITHM_OBJ randomAlgorithm;
{
  if (randomAlgorithm == NULL_PTR)
    return (0);

  return (AlgorithmWrapCheck ((AlgorithmWrap *)randomAlgorithm) ?
          BE_RANDOM_OBJ : 0);
}

