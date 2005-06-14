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
#include "intitem.h"
#include "aichgen.h"
#include "port_after.h"

int AIT_RSAKeyGenAddInfo PROTO_LIST
  ((THIS_ALGORITHM_INFO_TYPE *, B_Algorithm *, POINTER));

static A_RSA_KEY_GEN_PARAMS STATIC_KEY_GEN_PARAMS;
static ITEM *KEY_GEN_PARAMS_ITEMS[] = {&STATIC_KEY_GEN_PARAMS.publicExponent};

static B_AlgorithmInfoTypeVTable V_TABLE =
  {AIT_RSAKeyGenAddInfo, AITChooseGenerateNewHandler,
   B_AlgorithmInfoTypeMakeError};

B_AlgorithmInfoType AIT_RSAKeyGen = {&V_TABLE};

int AI_RSAKeyGen (infoType)
POINTER *infoType;
{
  *infoType = (POINTER)&AIT_RSAKeyGen;

  /* Return 0 to indicate a B_AlgorithmInfoType, not a B_KeyInfoType */
  return (0);
}

int AIT_RSAKeyGenAddInfo (infoType, algorithm, info)
B_AlgorithmInfoType *infoType;
B_Algorithm *algorithm;
POINTER info;
{
  A_RSA_KEY_GEN_PARAMS *newInfo;
  int status;
  
  if ((status = B_MemoryPoolAlloc
       (&algorithm->infoCache.memoryPool, (POINTER *)&newInfo,
        sizeof (A_RSA_KEY_GEN_PARAMS))) != 0)
      return (status);
  if ((status = AllocAndCopyIntegerItems
       ((POINTER)newInfo, info, (POINTER)&STATIC_KEY_GEN_PARAMS,
        KEY_GEN_PARAMS_ITEMS,
        sizeof (KEY_GEN_PARAMS_ITEMS) / sizeof (KEY_GEN_PARAMS_ITEMS[0]),
        &algorithm->infoCache.memoryPool)) != 0)
    return (status);

  newInfo->modulusBits = ((A_RSA_KEY_GEN_PARAMS *)info)->modulusBits;
  return (B_InfoCacheAddInfo
          (&algorithm->infoCache, (POINTER)infoType, (POINTER)newInfo));
}

