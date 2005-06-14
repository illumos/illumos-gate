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
#include "algobj.h"
#include "port_after.h"

int B_RandomInit
  (algorithmObject, algorithmChooser, surrenderContext)
B_ALGORITHM_OBJ algorithmObject;
B_ALGORITHM_CHOOSER algorithmChooser;
A_SURRENDER_CTX *surrenderContext;
{
  if (AlgorithmWrapCheck (THE_ALG_WRAP) != 0)
    /* Assume error is B_ALGORITHM_OBJ */
    return (BE_RANDOM_OBJ);

  return (B_AlgorithmRandomInit
          (&THE_ALG_WRAP->algorithm, algorithmChooser, surrenderContext));
}

int B_RandomUpdate (algorithmObject, input, inputLen, surrenderContext)
B_ALGORITHM_OBJ algorithmObject;
unsigned char *input;
unsigned int inputLen;
A_SURRENDER_CTX *surrenderContext;
{
  if (AlgorithmWrapCheck (THE_ALG_WRAP) != 0)
    /* Assume error is B_ALGORITHM_OBJ */
    return (BE_RANDOM_OBJ);

  return (B_AlgorithmRandomUpdate
          (&THE_ALG_WRAP->algorithm, input, inputLen, surrenderContext));
}

int B_GenerateRandomBytes
  (algorithmObject, output, outputLen, surrenderContext)
B_ALGORITHM_OBJ algorithmObject;
unsigned char *output;
unsigned int outputLen;
A_SURRENDER_CTX *surrenderContext;
{
  if (AlgorithmWrapCheck (THE_ALG_WRAP) != 0)
    /* Assume error is B_ALGORITHM_OBJ */
    return (BE_RANDOM_OBJ);

  return (B_AlgorithmGenerateRandomBytes
          (&THE_ALG_WRAP->algorithm, output, outputLen, surrenderContext));
}

