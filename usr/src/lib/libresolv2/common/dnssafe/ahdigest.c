/*
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#include "ahdigest.h"
#include "port_after.h"

static void TypedAHDigestDestructor PROTO_LIST ((B_TypeCheck *));

void AHDigestConstructor (handler)
AHDigest *handler;
{
  /* Construct base class, setting type tag. */
  B_TYPE_CHECK_Constructor
    (&handler->typeCheck, TypedAHDigestDestructor);

  /* Don't set vTable since this is a pure virtual base class. */
}

int B_AlgorithmDigestInit
  (algorithm, key, algorithmChooser, surrenderContext)
B_Algorithm *algorithm;
B_Key *key;
B_ALGORITHM_CHOOSER algorithmChooser;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = B_AlgorithmCheckType
       (algorithm, TypedAHDigestDestructor)) != 0)
    return (status);

  if ((status =
       (*((AHDigest *)algorithm->z.handler)->vTable->DigestInit)
       ((AHDigest *)algorithm->z.handler, key, algorithmChooser,
        surrenderContext)) != 0)
    return (status);

  algorithm->z.initFlag = 1;
  return (0);
}

int B_AlgorithmDigestUpdate (algorithm, partIn, partInLen, surrenderContext)
B_Algorithm *algorithm;
const unsigned char *partIn;
unsigned int partInLen;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = B_AlgorithmCheckTypeAndInitFlag
       (algorithm, TypedAHDigestDestructor)) != 0)
    return (status);

  return ((*((AHDigest *)algorithm->z.handler)->vTable->DigestUpdate)
          ((AHDigest *)algorithm->z.handler, partIn, partInLen,
           surrenderContext));
}

int B_AlgorithmDigestFinal
  (algorithm, partOut, partOutLen, maxPartOutLen, surrenderContext)
B_Algorithm *algorithm;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = B_AlgorithmCheckTypeAndInitFlag
       (algorithm, TypedAHDigestDestructor)) != 0)
    return (status);

  return ((*((AHDigest *)algorithm->z.handler)->vTable->DigestFinal)
          ((AHDigest *)algorithm->z.handler, partOut, partOutLen,
           maxPartOutLen, surrenderContext));
}

static void TypedAHDigestDestructor (typeCheck)
B_TypeCheck *typeCheck;
{
  (*((AHDigest *)typeCheck)->vTable->Destructor) ((AHDigest *)typeCheck);
}

