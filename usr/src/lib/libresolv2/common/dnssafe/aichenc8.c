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
#include "aichenc8.h"
#include "port_after.h"

B_AlgorithmInfoTypeVTable AITChooseEncrypt8_V_TABLE =
  {AIT_8AddInfo, AITChooseEncryptNewHandler, B_AlgorithmInfoTypeMakeError};

int AIT_8AddInfo (infoType, algorithm, info)
B_AlgorithmInfoType *infoType;
B_Algorithm *algorithm;
POINTER info;
{
  POINTER newInfo;
  int status;
  
  if ((status = B_MemoryPoolAllocAndCopy
       (&algorithm->infoCache.memoryPool, &newInfo, info, 8)) != 0)
    return (status);
  
  return (B_InfoCacheAddInfo
          (&algorithm->infoCache, (POINTER)infoType, newInfo));
}

