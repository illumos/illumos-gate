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
struct AHChooseGenerate;
#define THIS_GENERATE struct AHChooseGenerate

/* Define this so that the type of the AlgaChoice pointer in the
     INIT_ALGA functions will be correct for this derived class.
 */
struct GenerateAlgaChoice;
#define THIS_ALGA_CHOICE struct GenerateAlgaChoice

#include "port_before.h"
#include "global.h"
#include "algae.h"
#include "bsafe2.h"
#include "bkey.h"
#include "balg.h"
#include "balgmeth.h"
#include "ahchgen.h"
#include "amgen.h"
#include "port_after.h"

static int InitGenerateAlga PROTO_LIST
  ((GenerateAlgaChoice *, POINTER, B_ALGORITHM_METHOD *, A_SURRENDER_CTX *));
static int GenerateResult PROTO_LIST
  ((GenerateAlgaChoice *, POINTER *, B_Algorithm *, A_SURRENDER_CTX *));

static AHGenerateVTable V_TABLE = {
  AHChooseGenerateDestructor, AHChooseGenerateInit, AHChooseGenerateKeypair,
  AHChooseGenerateParameters
};

AHChooseGenerate *AHChooseGenerateConstructor2 (handler, infoType, info)
AHChooseGenerate *handler;
struct B_AlgorithmInfoType *infoType;
POINTER info;
{
  if (handler == (AHChooseGenerate *)NULL_PTR) {
    /* This constructor is being used to do a new */
    if ((handler = (AHChooseGenerate *)T_malloc (sizeof (*handler)))
        == (AHChooseGenerate *)NULL_PTR)
      return (handler);
  }

  /* Construct base class */
  AHGenerateConstructor (&handler->generate);

  ALGA_CHOICE_Constructor
    (&handler->generateAlgaChoice.algaChoice, InitGenerateAlga);
  ResizeContextConstructor (&handler->generateAlgaChoice.secondContext);
  ResizeContextConstructor (&handler->generateAlgaChoice.randomBlock);

  /* Set algaChoice.
   */
  handler->generateAlgaChoice.algaChoice._algorithmInfoType = infoType;
  handler->generateAlgaChoice.algaChoice._algorithmInfo = info;

  handler->generate.vTable = &V_TABLE;

  return (handler);
}

void AHChooseGenerateDestructor (handler)
AHChooseGenerate *handler;
{
  ResizeContextDestructor (&handler->generateAlgaChoice.secondContext);
  ResizeContextDestructor (&handler->generateAlgaChoice.randomBlock);
  ALGA_CHOICE_Destructor (&handler->generateAlgaChoice.algaChoice);
  /* There is no desructor to call for the base class. */
}

int AHChooseGenerateInit (handler, chooser, surrenderContext)
AHChooseGenerate *handler;
B_ALGORITHM_CHOOSER chooser;
A_SURRENDER_CTX *surrenderContext;
{
  return (AlgaChoiceChoose
          (&handler->generateAlgaChoice.algaChoice, 0, (B_Key *)NULL_PTR,
           chooser, surrenderContext));
}

int AHChooseGenerateKeypair
  (handler, publicKey, privateKey, randomAlgorithm, surrenderContext)
AHChooseGenerate *handler;
B_Key *publicKey;
B_Key *privateKey;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  POINTER result;
  int status;  
  
  if ((status = GenerateResult
       (&handler->generateAlgaChoice, &result, randomAlgorithm,
        surrenderContext)) != 0)
    return (status);
  if ((status = B_KeySetInfo
       (publicKey, handler->generateAlgaChoice._resultInfoType, result)) != 0)
    return (status);
  return (B_KeySetInfo
          (privateKey, handler->generateAlgaChoice._resultInfoType, result));
}

int AHChooseGenerateParameters
  (handler, resultAlgorithm, randomAlgorithm, surrenderContext)
AHChooseGenerate *handler;
B_Algorithm *resultAlgorithm;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  POINTER result;
  int status;  
  
  if ((status = GenerateResult
       (&handler->generateAlgaChoice, &result, randomAlgorithm,
        surrenderContext)) != 0)
    return (status);

  /* Force the resultInfoType into a B_AlgorithmInfoType since it is
       supplied in the chooser as a B_KeyInfoType. */
  return (B_AlgorithmSetInfo
          (resultAlgorithm, (struct B_AlgorithmInfoType *)
           handler->generateAlgaChoice._resultInfoType, result));
}

static int InitGenerateAlga
  (generateAlgaChoice, keyInfo, algorithmMethod, surrenderContext)
GenerateAlgaChoice *generateAlgaChoice;
POINTER keyInfo;
B_ALGORITHM_METHOD *algorithmMethod;
A_SURRENDER_CTX *surrenderContext;
{
  int status;
  unsigned int contextSize, secondContextSize;

UNUSED_ARG (keyInfo)
  /* Note that this also gets the resultInfoType which will be used later
       by GenerateResult. */
  if ((status = (*((A_GENERATE_ALGA *)algorithmMethod->alga)->Query)
       (&contextSize, &secondContextSize, &generateAlgaChoice->_randomBlockLen,
        &generateAlgaChoice->_resultInfoType,
        generateAlgaChoice->algaChoice._algorithmInfo)) != 0)
    return (ConvertAlgaeError (status));

  /* Create the context.
   */
  if ((status = ResizeContextMakeNewContext
       (&generateAlgaChoice->algaChoice.context, contextSize)) != 0)
    return (status);

  /* Create the second context which is only passed during Init, but
       must persist for all operations. */
  if ((status = ResizeContextMakeNewContext
       (&generateAlgaChoice->secondContext, secondContextSize)) != 0)
    return (status);

  /* Create randomBlock which will be filled in during GenerateResult. */
  if ((status = ResizeContextMakeNewContext
       (&generateAlgaChoice->randomBlock, generateAlgaChoice->_randomBlockLen))
      != 0)
    return (status);

  if ((status = (*((A_GENERATE_ALGA *)algorithmMethod->alga)->Init)
       (generateAlgaChoice->algaChoice.context.z.context,
        generateAlgaChoice->secondContext.z.context,
        generateAlgaChoice->algaChoice._algorithmInfo, surrenderContext)) != 0)
    return (ConvertAlgaeError (status));

   return (0);
}

/* Call the generate procedure repeatedly with a new random block
     until it succeeds.
 */
static int GenerateResult
  (generateAlgaChoice, result, randomAlgorithm, surrenderContext)
GenerateAlgaChoice *generateAlgaChoice;
POINTER *result;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  /* Fill in the random block and try generating as long as the
       the generate operation returns BE_NEED_RANDOM.
   */
  while (1) {
    if ((status = B_AlgorithmGenerateRandomBytes
         (randomAlgorithm,
          (unsigned char *)generateAlgaChoice->randomBlock.z.context,
          generateAlgaChoice->_randomBlockLen, surrenderContext)) != 0)
      return (status);

    if ((status = (*((A_GENERATE_ALGA *)
                     generateAlgaChoice->algaChoice._alga)->Generate)
         (generateAlgaChoice->algaChoice.context.z.context, result,
          (unsigned char *)generateAlgaChoice->randomBlock.z.context,
          surrenderContext)) != 0) {
      if (status != AE_NEED_RANDOM)
        return (ConvertAlgaeError (status));
      
      /* Else continue and try again */
    }
    else
      /* Success, so return */
      return (0);
  }
}

