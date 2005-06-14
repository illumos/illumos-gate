/*
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#include "keyobj.h"
#include "algobj.h"
#include "port_after.h"

int B_DigestInit
  (algorithmObject, keyObject, algorithmChooser, surrenderContext)
B_ALGORITHM_OBJ algorithmObject;
B_KEY_OBJ keyObject;
B_ALGORITHM_CHOOSER algorithmChooser;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = AlgorithmWrapCheck (THE_ALG_WRAP)) != 0)
    return (status);
  if ((status = KeyWrapCheck ((KeyWrap *)keyObject)) != 0)
    return (status);

  return (B_AlgorithmDigestInit
          (&THE_ALG_WRAP->algorithm, &((KeyWrap *)keyObject)->key,
           algorithmChooser, surrenderContext));
}

int B_DigestUpdate (algorithmObject, partIn, partInLen, surrenderContext)
B_ALGORITHM_OBJ algorithmObject;
const unsigned char *partIn;
unsigned int partInLen;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = AlgorithmWrapCheck (THE_ALG_WRAP)) != 0)
    return (status);

  return (B_AlgorithmDigestUpdate
          (&THE_ALG_WRAP->algorithm, partIn, partInLen, surrenderContext));
}

int B_DigestFinal
  (algorithmObject, digest, digestLen, maxDigestLen, surrenderContext)
B_ALGORITHM_OBJ algorithmObject;
unsigned char *digest;
unsigned int *digestLen;
unsigned int maxDigestLen;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = AlgorithmWrapCheck (THE_ALG_WRAP)) != 0)
    return (status);

  return (B_AlgorithmDigestFinal
          (&THE_ALG_WRAP->algorithm, digest, digestLen, maxDigestLen,
           surrenderContext));
}

