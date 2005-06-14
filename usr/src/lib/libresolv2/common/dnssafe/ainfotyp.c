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
#include "ainfotyp.h"
#include "port_after.h"

/* This is the default routine which algorithm info types point MakeInfo to
     if not redefined by a derived class.
 */
int B_AlgorithmInfoTypeMakeError (infoType, info, algorithm)
B_AlgorithmInfoType *infoType;
POINTER *info;
B_Algorithm *algorithm;
{
UNUSED_ARG (infoType)
UNUSED_ARG (info)
UNUSED_ARG (algorithm)

  /* Should already have been found in the cache. */
  return (BE_WRONG_ALGORITHM_INFO);
}

