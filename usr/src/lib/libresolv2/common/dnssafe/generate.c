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
#include "keyobj.h"
#include "algobj.h"
#include "port_after.h"

int B_GenerateInit (algorithmObject, algorithmChooser, surrenderContext)
B_ALGORITHM_OBJ algorithmObject;
B_ALGORITHM_CHOOSER algorithmChooser;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = AlgorithmWrapCheck (THE_ALG_WRAP)) != 0)
    return (status);

  return (B_AlgorithmGenerateInit
          (&THE_ALG_WRAP->algorithm, algorithmChooser, surrenderContext));
}

int B_GenerateKeypair
  (algorithmObject, publicKey, privateKey, randomAlgorithm, surrenderContext)
B_ALGORITHM_OBJ algorithmObject;
B_KEY_OBJ publicKey;
B_KEY_OBJ privateKey;
B_ALGORITHM_OBJ randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = AlgorithmWrapCheck (THE_ALG_WRAP)) != 0)
    return (status);
  if ((status = KeyWrapCheck ((KeyWrap *)publicKey)) != 0)
    return (status);
  if ((status = KeyWrapCheck ((KeyWrap *)privateKey)) != 0)
    return (status);
  if ((status = RandomAlgorithmCheck (randomAlgorithm)) != 0)
    return (status);

  return (B_AlgorithmGenerateKeypair
          (&THE_ALG_WRAP->algorithm, &((KeyWrap *)publicKey)->key,
           &((KeyWrap *)privateKey)->key,
           &((AlgorithmWrap *)randomAlgorithm)->algorithm, surrenderContext));
}

int B_GenerateParameters
  (algorithmObject, resultAlgorithmObject, randomAlgorithm, surrenderContext)
B_ALGORITHM_OBJ algorithmObject;
B_ALGORITHM_OBJ resultAlgorithmObject;
B_ALGORITHM_OBJ randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = AlgorithmWrapCheck (THE_ALG_WRAP)) != 0)
    return (status);
  if ((status = AlgorithmWrapCheck ((AlgorithmWrap *)resultAlgorithmObject))
      != 0)
    return (status);
  if ((status = RandomAlgorithmCheck (randomAlgorithm)) != 0)
    return (status);

  return (B_AlgorithmGenerateParameters
          (&THE_ALG_WRAP->algorithm,
           &((AlgorithmWrap *)resultAlgorithmObject)->algorithm,
           &((AlgorithmWrap *)randomAlgorithm)->algorithm, surrenderContext));
}

