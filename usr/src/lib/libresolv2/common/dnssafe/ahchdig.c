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

/* Define this so that the type of the 'this' pointer in the
     virtual functions will be correct for this derived class.
 */
struct AHChooseDigest;
#define THIS_DIGEST struct AHChooseDigest

#include "port_before.h"
#include "global.h"
#include "algae.h"
#include "bsafe2.h"
#include "bkey.h"
#include "balg.h"
#include "balgmeth.h"
#include "ahchdig.h"
#include "amdigest.h"
#include "port_after.h"

static int InitDigestAlga PROTO_LIST
  ((AlgaChoice *, POINTER, B_ALGORITHM_METHOD *, A_SURRENDER_CTX *));

static AHDigestVTable V_TABLE = {
  AHChooseDigestDestructor, AHChooseDigestInit, AHChooseDigestUpdate,
  AHChooseDigestFinal
};

AHChooseDigest *AHChooseDigestConstructor2 (handler, infoType, info)
AHChooseDigest *handler;
struct B_AlgorithmInfoType *infoType;
POINTER info;
{
  if (handler == (AHChooseDigest *)NULL_PTR) {
    /* This constructor is being used to do a new */
    if ((handler = (AHChooseDigest *)T_malloc (sizeof (*handler)))
        == (AHChooseDigest *)NULL_PTR)
      return (handler);
  }

  /* Construct base class */
  AHDigestConstructor (&handler->digest);

  ALGA_CHOICE_Constructor (&handler->algaChoice, InitDigestAlga);
  handler->algaChoice._algorithmInfoType = infoType;
  handler->algaChoice._algorithmInfo = info;

  handler->digest.vTable = &V_TABLE;

  return (handler);
}

void AHChooseDigestDestructor (handler)
AHChooseDigest *handler;
{
  ALGA_CHOICE_Destructor (&handler->algaChoice);
  /* There is no desructor to call for the base class. */
}

int AHChooseDigestInit (handler, key, chooser, surrenderContext)
AHChooseDigest *handler;
B_Key *key;
B_ALGORITHM_CHOOSER chooser;
A_SURRENDER_CTX *surrenderContext;
{
  return (AlgaChoiceChoose
          (&handler->algaChoice, 0, key, chooser, surrenderContext));
}

int AHChooseDigestUpdate (handler, partIn, partInLen, surrenderContext)
AHChooseDigest *handler;
const unsigned char *partIn;
unsigned int partInLen;
A_SURRENDER_CTX *surrenderContext;
{
  int status;
  
  if ((status = (*((A_DIGEST_ALGA *)handler->algaChoice._alga)->Update)
       (handler->algaChoice.context.z.context, partIn, partInLen,
        surrenderContext)) != 0)
    return (ConvertAlgaeError (status));
  return (0);    
}

int AHChooseDigestFinal
  (handler, partOut, partOutLen, maxPartOutLen, surrenderContext)
AHChooseDigest *handler;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
A_SURRENDER_CTX *surrenderContext;
{
  int status;
  
  if ((status = (*((A_DIGEST_ALGA *)handler->algaChoice._alga)->Final)
       (handler->algaChoice.context.z.context, partOut, partOutLen,
        maxPartOutLen, surrenderContext)) != 0)
    return (ConvertAlgaeError (status));
  return (0);    
}

static int InitDigestAlga
  (algaChoice, keyInfo, algorithmMethod, surrenderContext)
AlgaChoice *algaChoice;
POINTER keyInfo;
B_ALGORITHM_METHOD *algorithmMethod;
A_SURRENDER_CTX *surrenderContext;
{
  int status;
  unsigned int contextSize;

UNUSED_ARG (keyInfo)
  if ((status = (*((A_DIGEST_ALGA *)algorithmMethod->alga)->Query)
       (&contextSize, algaChoice->_algorithmInfo)) != 0)
    return (ConvertAlgaeError (status));

  if ((status = ResizeContextMakeNewContext
       (&algaChoice->context, contextSize)) != 0)
    return (status);

  if ((status = (*((A_DIGEST_ALGA *)algorithmMethod->alga)->Init)
       (algaChoice->context.z.context, algaChoice->_algorithmInfo,
        surrenderContext)) != 0)
    return (ConvertAlgaeError (status));

  return (0);
}
