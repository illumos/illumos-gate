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
#include "aichencn.h"
#include "port_after.h"

B_AlgorithmInfoType AIT_RSAPublic = {&AITChooseEncryptNull_V_TABLE};

int AI_RSAPublic (infoType)
POINTER *infoType;
{
  *infoType = (POINTER)&AIT_RSAPublic;

  /* Return 0 to indicate a B_AlgorithmInfoType, not a B_KeyInfoType */
  return (0);
}

