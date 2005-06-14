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
#include "ainull.h"
#include "ahrsaepr.h"
#include "port_after.h"

B_TypeCheck *AIT_PKCS_RSAPrivateNewHandler PROTO_LIST
  ((B_AlgorithmInfoType *, B_Algorithm *));

static B_AlgorithmInfoTypeVTable V_TABLE =
  {AITNullAddInfo, AIT_PKCS_RSAPrivateNewHandler,
   B_AlgorithmInfoTypeMakeError};

B_AlgorithmInfoType AIT_PKCS_RSAPrivate = {&V_TABLE};

int AI_PKCS_RSAPrivate (infoType)
POINTER *infoType;
{
  *infoType = (POINTER)&AIT_PKCS_RSAPrivate;

  /* Return 0 to indicate a B_AlgorithmInfoType, not a B_KeyInfoType */
  return (0);
}

B_TypeCheck *AIT_PKCS_RSAPrivateNewHandler (infoType, algorithm)
B_AlgorithmInfoType *infoType;
B_Algorithm *algorithm;
{
UNUSED_ARG (infoType)
UNUSED_ARG (algorithm)
  /* Pass in NULL_PTR so that constructor will allocate. */
  return ((B_TypeCheck *)AH_RSAEncrypPrivateConstructor
          ((AH_RSAEncryptionPrivate *)NULL_PTR));
}

