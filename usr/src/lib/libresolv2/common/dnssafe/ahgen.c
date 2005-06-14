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
#include "ahgen.h"
#include "port_after.h"

static void TypedAHGenerateDestructor PROTO_LIST ((B_TypeCheck *));

void AHGenerateConstructor (handler)
AHGenerate *handler;
{
  /* Construct base class, setting type tag. */
  B_TYPE_CHECK_Constructor
    (&handler->typeCheck, TypedAHGenerateDestructor);

  /* Don't set vTable since this is a pure virtual base class. */
}

int B_AlgorithmGenerateInit (algorithm, algorithmChooser, surrenderContext)
B_Algorithm *algorithm;
B_ALGORITHM_CHOOSER algorithmChooser;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = B_AlgorithmCheckType
       (algorithm, TypedAHGenerateDestructor)) != 0)
    return (status);

  if ((status =
       (*((AHGenerate *)algorithm->z.handler)->vTable->GenerateInit)
       ((AHGenerate *)algorithm->z.handler, algorithmChooser,
        surrenderContext)) != 0)
    return (status);

  algorithm->z.initFlag = 1;
  return (0);
}

int B_AlgorithmGenerateKeypair
  (algorithm, publicKey, privateKey, randomAlgorithm, surrenderContext)
B_Algorithm *algorithm;
B_Key *publicKey;
B_Key *privateKey;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = B_AlgorithmCheckTypeAndInitFlag
       (algorithm, TypedAHGenerateDestructor)) != 0)
    return (status);

  return ((*((AHGenerate *)algorithm->z.handler)->vTable->GenerateKeypair)
          ((AHGenerate *)algorithm->z.handler, publicKey, privateKey,
           randomAlgorithm, surrenderContext));
}

int B_AlgorithmGenerateParameters
  (algorithm, resultAlgorithm, randomAlgorithm, surrenderContext)
B_Algorithm *algorithm;
B_Algorithm *resultAlgorithm;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = B_AlgorithmCheckTypeAndInitFlag
       (algorithm, TypedAHGenerateDestructor)) != 0)
    return (status);

  return ((*((AHGenerate *)algorithm->z.handler)->vTable->GenerateParameters)
          ((AHGenerate *)algorithm->z.handler, resultAlgorithm,
           randomAlgorithm, surrenderContext));
}

static void TypedAHGenerateDestructor (typeCheck)
B_TypeCheck *typeCheck;
{
  (*((AHGenerate *)typeCheck)->vTable->Destructor) ((AHGenerate *)typeCheck);
}

