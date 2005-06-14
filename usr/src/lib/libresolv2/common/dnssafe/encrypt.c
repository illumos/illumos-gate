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

int B_EncryptInit
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

  return (B_AlgorithmEncryptInit
          (&THE_ALG_WRAP->algorithm, &((KeyWrap *)keyObject)->key,
           algorithmChooser, surrenderContext));
}

int B_EncryptUpdate
  (algorithmObject, partOut, partOutLen, maxPartOutLen, partIn, partInLen,
   randomAlgorithm, surrenderContext)
B_ALGORITHM_OBJ algorithmObject;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
unsigned char *partIn;
unsigned int partInLen;
B_ALGORITHM_OBJ randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = AlgorithmWrapCheck (THE_ALG_WRAP)) != 0)
    return (status);
  if ((status = RandomAlgorithmCheck (randomAlgorithm)) != 0)
    return (status);

  return (B_AlgorithmEncryptUpdate
          (&THE_ALG_WRAP->algorithm, partOut, partOutLen, maxPartOutLen,
           partIn, partInLen,
           &((AlgorithmWrap *)randomAlgorithm)->algorithm, surrenderContext));
}

int B_EncryptFinal
  (algorithmObject, partOut, partOutLen, maxPartOutLen, randomAlgorithm,
   surrenderContext)
B_ALGORITHM_OBJ algorithmObject;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
B_ALGORITHM_OBJ randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = AlgorithmWrapCheck (THE_ALG_WRAP)) != 0)
    return (status);
  if ((status = RandomAlgorithmCheck (randomAlgorithm)) != 0)
    return (status);

  return (B_AlgorithmEncryptFinal
          (&THE_ALG_WRAP->algorithm, partOut, partOutLen, maxPartOutLen,
           &((AlgorithmWrap *)randomAlgorithm)->algorithm, surrenderContext));
}

int B_DecryptInit
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

  return (B_AlgorithmDecryptInit
          (&THE_ALG_WRAP->algorithm, &((KeyWrap *)keyObject)->key,
           algorithmChooser, surrenderContext));
}

int B_DecryptUpdate
  (algorithmObject, partOut, partOutLen, maxPartOutLen, partIn, partInLen,
   randomAlgorithm, surrenderContext)
B_ALGORITHM_OBJ algorithmObject;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
const unsigned char *partIn;
unsigned int partInLen;
B_ALGORITHM_OBJ randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = AlgorithmWrapCheck (THE_ALG_WRAP)) != 0)
    return (status);
  if ((status = RandomAlgorithmCheck (randomAlgorithm)) != 0)
    return (status);

  return (B_AlgorithmDecryptUpdate
          (&THE_ALG_WRAP->algorithm, partOut, partOutLen, maxPartOutLen,
           partIn, partInLen,
           &((AlgorithmWrap *)randomAlgorithm)->algorithm, surrenderContext));
}

int B_DecryptFinal
  (algorithmObject, partOut, partOutLen, maxPartOutLen, randomAlgorithm,
   surrenderContext)
B_ALGORITHM_OBJ algorithmObject;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
B_ALGORITHM_OBJ randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = AlgorithmWrapCheck (THE_ALG_WRAP)) != 0)
    return (status);
  if ((status = RandomAlgorithmCheck (randomAlgorithm)) != 0)
    return (status);

  return (B_AlgorithmDecryptFinal
          (&THE_ALG_WRAP->algorithm, partOut, partOutLen, maxPartOutLen,
           &((AlgorithmWrap *)randomAlgorithm)->algorithm, surrenderContext));
}

