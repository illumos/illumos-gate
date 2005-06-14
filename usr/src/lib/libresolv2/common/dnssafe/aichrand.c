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
#include "ahchrand.h"
#include "aichrand.h"
#include "port_after.h"

B_TypeCheck *AITChooseRandomNullNewHandler PROTO_LIST
  ((B_AlgorithmInfoType *, B_Algorithm *));

B_AlgorithmInfoTypeVTable AITChooseRandomNull_V_TABLE =
  {AITNullAddInfo, AITChooseRandomNullNewHandler,
   B_AlgorithmInfoTypeMakeError};

/* This always uses NULL_PTR for the info.
 */
B_TypeCheck *AITChooseRandomNullNewHandler (infoType, algorithm)
B_AlgorithmInfoType *infoType;
B_Algorithm *algorithm;
{
UNUSED_ARG (algorithm)

  /* Pass in NULL_PTR so that constructor will allocate.
   */
  return ((B_TypeCheck *)AHChooseRandomConstructor2
          ((AHChooseRandom *)NULL_PTR, infoType, NULL_PTR));
}

