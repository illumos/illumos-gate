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
#include "ahencryp.h"
#include "port_after.h"

static void TypedAHEncryptDecryptDestructor PROTO_LIST ((B_TypeCheck *));

void AHEncryptDecryptConstructor (handler)
AHEncryptDecrypt *handler;
{
  /* Construct base class, setting type tag. */
  B_TYPE_CHECK_Constructor
    (&handler->typeCheck, TypedAHEncryptDecryptDestructor);

  /* Don't set vTable since this is a pure virtual base class. */
}

int B_AlgorithmEncryptInit
  (algorithm, key, algorithmChooser, surrenderContext)
B_Algorithm *algorithm;
B_Key *key;
B_ALGORITHM_CHOOSER algorithmChooser;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = B_AlgorithmCheckType
       (algorithm, TypedAHEncryptDecryptDestructor)) != 0)
    return (status);

  if ((status =
       (*((AHEncryptDecrypt *)algorithm->z.handler)->vTable->EncryptInit)
       ((AHEncryptDecrypt *)algorithm->z.handler, key, algorithmChooser,
        surrenderContext)) != 0)
    return (status);

  algorithm->z.initFlag = 1;
  return (0);
}

int B_AlgorithmDecryptInit
  (algorithm, key, algorithmChooser, surrenderContext)
B_Algorithm *algorithm;
B_Key *key;
B_ALGORITHM_CHOOSER algorithmChooser;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = B_AlgorithmCheckType
       (algorithm, TypedAHEncryptDecryptDestructor)) != 0)
    return (status);

  if ((status =
       (*((AHEncryptDecrypt *)algorithm->z.handler)->vTable->DecryptInit)
       ((AHEncryptDecrypt *)algorithm->z.handler, key, algorithmChooser,
        surrenderContext)) != 0)
    return (status);

  algorithm->z.initFlag = 1;
  return (0);
}

int B_AlgorithmEncryptUpdate
  (algorithm, partOut, partOutLen, maxPartOutLen, partIn, partInLen,
   randomAlgorithm, surrenderContext)
B_Algorithm *algorithm;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
unsigned char *partIn;
unsigned int partInLen;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = B_AlgorithmCheckTypeAndInitFlag
       (algorithm, TypedAHEncryptDecryptDestructor)) != 0)
    return (status);

  return ((*((AHEncryptDecrypt *)algorithm->z.handler)->vTable->EncryptUpdate)
          ((AHEncryptDecrypt *)algorithm->z.handler, partOut, partOutLen,
           maxPartOutLen, partIn, partInLen, randomAlgorithm,
           surrenderContext));
}

int B_AlgorithmDecryptUpdate
  (algorithm, partOut, partOutLen, maxPartOutLen, partIn, partInLen,
   randomAlgorithm, surrenderContext)
B_Algorithm *algorithm;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
const unsigned char *partIn;
unsigned int partInLen;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = B_AlgorithmCheckTypeAndInitFlag
       (algorithm, TypedAHEncryptDecryptDestructor)) != 0)
    return (status);

  return ((*((AHEncryptDecrypt *)algorithm->z.handler)->vTable->DecryptUpdate)
          ((AHEncryptDecrypt *)algorithm->z.handler, partOut, partOutLen,
           maxPartOutLen, partIn, partInLen, randomAlgorithm,
           surrenderContext));
}

int B_AlgorithmEncryptFinal
  (algorithm, partOut, partOutLen, maxPartOutLen, randomAlgorithm,
   surrenderContext)
B_Algorithm *algorithm;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = B_AlgorithmCheckTypeAndInitFlag
       (algorithm, TypedAHEncryptDecryptDestructor)) != 0)
    return (status);

  return ((*((AHEncryptDecrypt *)algorithm->z.handler)->vTable->EncryptFinal)
          ((AHEncryptDecrypt *)algorithm->z.handler, partOut, partOutLen,
           maxPartOutLen, randomAlgorithm, surrenderContext));
}

int B_AlgorithmDecryptFinal
  (algorithm, partOut, partOutLen, maxPartOutLen, randomAlgorithm,
   surrenderContext)
B_Algorithm *algorithm;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = B_AlgorithmCheckTypeAndInitFlag
       (algorithm, TypedAHEncryptDecryptDestructor)) != 0)
    return (status);

  return ((*((AHEncryptDecrypt *)algorithm->z.handler)->vTable->DecryptFinal)
          ((AHEncryptDecrypt *)algorithm->z.handler, partOut, partOutLen,
           maxPartOutLen, randomAlgorithm, surrenderContext));
}

static void TypedAHEncryptDecryptDestructor (typeCheck)
B_TypeCheck *typeCheck;
{
  (*((AHEncryptDecrypt *)typeCheck)->vTable->Destructor)
    ((AHEncryptDecrypt *)typeCheck);
}

