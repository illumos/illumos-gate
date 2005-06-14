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

/* Define this so that the type of the 'this' pointer in the
     virtual functions will be correct for this derived class.
 */
struct AHChooseRandom;
#define THIS_RANDOM struct AHChooseRandom

#include "port_before.h"
#include "global.h"
#include "algae.h"
#include "bsafe2.h"
#include "bkey.h"
#include "balg.h"
#include "balgmeth.h"
#include "ahchrand.h"
#include "amrandom.h"
#include "port_after.h"

static int InitRandomAlga PROTO_LIST
  ((AlgaChoice *, POINTER, B_ALGORITHM_METHOD *, A_SURRENDER_CTX *));

static AHRandomVTable V_TABLE = {
  AHChooseRandomDestructor, AHChooseRandomInit, AHChooseRandomUpdate,
  AHChooseRandomGenerateBytes
};

AHChooseRandom *AHChooseRandomConstructor2 (handler, infoType, info)
AHChooseRandom *handler;
struct B_AlgorithmInfoType *infoType;
POINTER info;
{
  if (handler == (AHChooseRandom *)NULL_PTR) {
    /* This constructor is being used to do a new */
    if ((handler = (AHChooseRandom *)T_malloc (sizeof (*handler)))
        == (AHChooseRandom *)NULL_PTR)
      return (handler);
  }

  /* Construct base class */
  AHRandomConstructor (&handler->random);

  ALGA_CHOICE_Constructor (&handler->algaChoice, InitRandomAlga);
  handler->algaChoice._algorithmInfoType = infoType;
  handler->algaChoice._algorithmInfo = info;

  handler->random.vTable = &V_TABLE;

  return (handler);
}

void AHChooseRandomDestructor (handler)
AHChooseRandom *handler;
{
  ALGA_CHOICE_Destructor (&handler->algaChoice);
  /* There is no desructor to call for the base class. */
}

int AHChooseRandomInit (handler, chooser, surrenderContext)
AHChooseRandom *handler;
B_ALGORITHM_CHOOSER chooser;
A_SURRENDER_CTX *surrenderContext;
{
  return (AlgaChoiceChoose
          (&handler->algaChoice, 0, (B_Key *)NULL_PTR, chooser,
           surrenderContext));
}

int AHChooseRandomUpdate (handler, input, inputLen, surrenderContext)
AHChooseRandom *handler;
unsigned char *input;
unsigned int inputLen;
A_SURRENDER_CTX *surrenderContext;
{
  int status;
  
  if ((status = (*((A_RANDOM_ALGA *)handler->algaChoice._alga)->Update)
       (handler->algaChoice.context.z.context, input, inputLen,
        surrenderContext)) != 0)
    return (ConvertAlgaeError (status));
  return (0);    
}

int AHChooseRandomGenerateBytes (handler, output, outputLen, surrenderContext)
AHChooseRandom *handler;
unsigned char *output;
unsigned int outputLen;
A_SURRENDER_CTX *surrenderContext;
{
  int status;
  
  if ((status = (*((A_RANDOM_ALGA *)handler->algaChoice._alga)->Generate)
       (handler->algaChoice.context.z.context, output, outputLen,
        surrenderContext)) != 0)
    return (ConvertAlgaeError (status));
  return (0);    
}

static int InitRandomAlga
  (algaChoice, keyInfo, algorithmMethod, surrenderContext)
AlgaChoice *algaChoice;
POINTER keyInfo;
B_ALGORITHM_METHOD *algorithmMethod;
A_SURRENDER_CTX *surrenderContext;
{
  int status;
  unsigned int contextSize;

UNUSED_ARG (keyInfo)
  if ((status = (*((A_RANDOM_ALGA *)algorithmMethod->alga)->Query)
       (&contextSize, algaChoice->_algorithmInfo)) != 0)
    return (ConvertAlgaeError (status));

  if ((status = ResizeContextMakeNewContext
       (&algaChoice->context, contextSize)) != 0)
    return (status);

  if ((status = (*((A_RANDOM_ALGA *)algorithmMethod->alga)->Init)
       (algaChoice->context.z.context, algaChoice->_algorithmInfo,
        surrenderContext)) != 0)
    return (ConvertAlgaeError (status));

  return (0);
}
