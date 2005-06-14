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
#include "ahrandom.h"
#include "port_after.h"

static void TypedAHRandomDestructor PROTO_LIST ((B_TypeCheck *));

void AHRandomConstructor (handler)
AHRandom *handler;
{
  /* Construct base class, setting type tag. */
  B_TYPE_CHECK_Constructor
    (&handler->typeCheck, TypedAHRandomDestructor);

  /* Don't set vTable since this is a pure virtual base class. */
}

int B_AlgorithmRandomInit (algorithm, algorithmChooser, surrenderContext)
B_Algorithm *algorithm;
B_ALGORITHM_CHOOSER algorithmChooser;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = B_AlgorithmCheckType (algorithm, TypedAHRandomDestructor))
      != 0)
    return (status);

  if ((status =
       (*((AHRandom *)algorithm->z.handler)->vTable->RandomInit)
       ((AHRandom *)algorithm->z.handler, algorithmChooser, surrenderContext))
      != 0)
    return (status);

  algorithm->z.initFlag = 1;
  return (0);
}

int B_AlgorithmRandomUpdate (algorithm, input, inputLen, surrenderContext)
B_Algorithm *algorithm;
unsigned char *input;
unsigned int inputLen;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = B_AlgorithmCheckTypeAndInitFlag
       (algorithm, TypedAHRandomDestructor)) != 0)
    return (status == BE_ALGORITHM_NOT_INITIALIZED ?
            BE_RANDOM_NOT_INITIALIZED : status);

  return ((*((AHRandom *)algorithm->z.handler)->vTable->RandomUpdate)
          ((AHRandom *)algorithm->z.handler, input, inputLen,
           surrenderContext));
}

int B_AlgorithmGenerateRandomBytes
  (algorithm, output, outputLen, surrenderContext)
B_Algorithm *algorithm;
unsigned char *output;
unsigned int outputLen;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  /* As a special case, check here for a null this pointer when the object
       is actually being used since many routines take a "dummy" null
       random algorithm.
   */
  if (algorithm == (B_Algorithm *)NULL_PTR)
    return (BE_RANDOM_OBJ);

  if ((status = B_AlgorithmCheckTypeAndInitFlag
       (algorithm, TypedAHRandomDestructor)) != 0)
    return (status == BE_ALGORITHM_NOT_INITIALIZED ?
            BE_RANDOM_NOT_INITIALIZED : status);

  return ((*((AHRandom *)algorithm->z.handler)->vTable->GenerateBytes)
          ((AHRandom *)algorithm->z.handler, output, outputLen,
           surrenderContext));
}

static void TypedAHRandomDestructor (typeCheck)
B_TypeCheck *typeCheck;
{
  (*((AHRandom *)typeCheck)->vTable->Destructor) ((AHRandom *)typeCheck);
}

