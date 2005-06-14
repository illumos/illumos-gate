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
struct AHChooseEncryptDecrypt;
#define THIS_ENCRYPT_DECRYPT struct AHChooseEncryptDecrypt

#include "port_before.h"
#include "global.h"
#include "algae.h"
#include "bsafe2.h"
#include "bkey.h"
#include "balg.h"
#include "balgmeth.h"
#include "ahchencr.h"
#include "amencdec.h"
#include "port_after.h"

static int InitEncryptDecryptAlga PROTO_LIST
  ((AlgaChoice *, POINTER, B_ALGORITHM_METHOD *, A_SURRENDER_CTX *));

static AHEncryptDecryptVTable V_TABLE = {
  AHChooseEncryptDestructor, AHChooseEncryptGetBlockLen,
  AHChooseEncryptEncryptInit, AHChooseEncryptDecryptInit,
  AHChooseEncryptEncryptUpdate, AHChooseEncryptDecryptUpdate,
  AHChooseEncryptEncryptFinal, AHChooseEncryptDecryptFinal
};

/* In C++:
AHChooseEncryptDecrypt::AHChooseEncryptDecrypt
  (B_AlgorithmInfoType *infoType, POINTER info)
  : algaChoice (InitEncryptDecryptAlga)
{
  algaChoice.setAlgorithmInfoType (infoType);
  algaChoice.setAlgorithmInfo (info);
}
 */
AHChooseEncryptDecrypt *AHChooseEncryptConstructor2 (handler, infoType, info)
AHChooseEncryptDecrypt *handler;
struct B_AlgorithmInfoType *infoType;
POINTER info;
{
  if (handler == (AHChooseEncryptDecrypt *)NULL_PTR) {
    /* This constructor is being used to do a new */
    if ((handler = (AHChooseEncryptDecrypt *)T_malloc (sizeof (*handler)))
        == (AHChooseEncryptDecrypt *)NULL_PTR)
      return (handler);
  }

  /* Construct base class */
  AHEncryptDecryptConstructor (&handler->encryptDecrypt);

  ALGA_CHOICE_Constructor (&handler->algaChoice, InitEncryptDecryptAlga);
  handler->algaChoice._algorithmInfoType = infoType;
  handler->algaChoice._algorithmInfo = info;

  handler->encryptDecrypt.vTable = &V_TABLE;

  return (handler);
}

void AHChooseEncryptDestructor (handler)
AHChooseEncryptDecrypt *handler;
{
  ALGA_CHOICE_Destructor (&handler->algaChoice);
  /* There is no desructor to call for the base class. */
}

int AHChooseEncryptGetBlockLen (handler, blockLen)
AHChooseEncryptDecrypt *handler;
unsigned int *blockLen;
{
  int status;

  if ((status = (*((A_ENCRYPT_DECRYPT_ALGA *)handler->algaChoice._alga)->
                 GetBlockLen)
       (handler->algaChoice.context.z.context, blockLen)) != 0)
    return (ConvertAlgaeError (status));
  return (0);
}

/* In C++:
int AHChooseEncryptDecrypt::encryptInit
  (B_Key *key, B_ALGORITHM_CHOOSER chooser, A_SURRENDER_CTX *surrenderContext)
{
  return (algaChoice.choose (1, key, chooser, surrenderContext));
}
 */
int AHChooseEncryptEncryptInit (handler, key, chooser, surrenderContext)
AHChooseEncryptDecrypt *handler;
B_Key *key;
B_ALGORITHM_CHOOSER chooser;
A_SURRENDER_CTX *surrenderContext;
{
  return (AlgaChoiceChoose
          (&handler->algaChoice, 1, key, chooser, surrenderContext));
}

int AHChooseEncryptDecryptInit (handler, key, chooser, surrenderContext)
AHChooseEncryptDecrypt *handler;
B_Key *key;
B_ALGORITHM_CHOOSER chooser;
A_SURRENDER_CTX *surrenderContext;
{
  return (AlgaChoiceChoose
          (&handler->algaChoice, 0, key, chooser, surrenderContext));
}

/* In C++:
int AHChooseEncryptDecrypt::encryptUpdate
  (unsigned char *partOut, unsigned int *partOutLen,
   unsigned int maxPartOutLen, unsigned char *partIn, unsigned int partInLen,
   B_Algorithm *randomAlgorithm, A_SURRENDER_CTX *surrenderContext)
{
  int status;

  if ((status = (*((A_ENCRYPT_DECRYPT_ALGA *)algaChoice.alga ()) ->Update)
       (algaChoice.context (), partOut, partOutLen, maxPartOutLen,
        partIn, partInLen, surrenderContext)) != 0)
    return (ConvertAlgaeError (status));
  return (0);
}  
 */
int AHChooseEncryptEncryptUpdate
  (handler, partOut, partOutLen, maxPartOutLen, partIn, partInLen,
   randomAlgorithm, surrenderContext)
AHChooseEncryptDecrypt *handler;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
const unsigned char *partIn;
unsigned int partInLen;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

UNUSED_ARG (randomAlgorithm)

  if ((status = (*((A_ENCRYPT_DECRYPT_ALGA *)handler->algaChoice._alga)->
                 Update)
       (handler->algaChoice.context.z.context, partOut, partOutLen,
        maxPartOutLen, partIn, partInLen, surrenderContext)) != 0)
    return (ConvertAlgaeError (status));
  return (0);
}

int AHChooseEncryptDecryptUpdate
  (handler, partOut, partOutLen, maxPartOutLen, partIn, partInLen,
   randomAlgorithm, surrenderContext)
AHChooseEncryptDecrypt *handler;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
const unsigned char *partIn;
unsigned int partInLen;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

UNUSED_ARG (randomAlgorithm)

  if ((status = (*((A_ENCRYPT_DECRYPT_ALGA *)handler->algaChoice._alga)->
                 Update)
       (handler->algaChoice.context.z.context, partOut, partOutLen,
        maxPartOutLen, partIn, partInLen, surrenderContext)) != 0)
    return (ConvertAlgaeError (status));
  return (0);
}

int AHChooseEncryptEncryptFinal
  (handler, partOut, partOutLen, maxPartOutLen, randomAlgorithm,
   surrenderContext)
AHChooseEncryptDecrypt *handler;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

UNUSED_ARG (randomAlgorithm)

  if ((status = (*((A_ENCRYPT_DECRYPT_ALGA *)handler->algaChoice._alga)->Final)
       (handler->algaChoice.context.z.context, partOut, partOutLen,
        maxPartOutLen, surrenderContext)) != 0)
    return (ConvertAlgaeError (status));
  return (0);
}

int AHChooseEncryptDecryptFinal
  (handler, partOut, partOutLen, maxPartOutLen, randomAlgorithm,
   surrenderContext)
AHChooseEncryptDecrypt *handler;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

UNUSED_ARG (randomAlgorithm)

  if ((status = (*((A_ENCRYPT_DECRYPT_ALGA *)handler->algaChoice._alga)->Final)
       (handler->algaChoice.context.z.context, partOut, partOutLen,
        maxPartOutLen, surrenderContext)) != 0)
    return (ConvertAlgaeError (status));
  return (0);
}

/* In C++:
static int InitEncryptDecryptAlga
  (AlgaChoice *algaChoice, POINTER keyInfo, POINTER alga,
   A_SURRENDER_CTX *surrenderContext)
{
  int status;
  unsigned int contextSize;

  if ((status = (*((A_ENCRYPT_DECRYPT_ALGA *)alga)->Query)
       (&contextSize, keyInfo, algaChoice->algorithmInfo ())) != 0)
    return (ConvertAlgaeError (status));

  if ((status = algaChoice->makeNewContext (contextSize)) != 0)
    return (status);

  if ((status = (*((A_ENCRYPT_DECRYPT_ALGA *)alga)->Init)
       (algaChoice->context (), keyInfo, algaChoice->algorithmInfo (),
        surrenderContext)) != 0)
    return (ConvertAlgaeError (status));

  return (0);
}
 */
static int InitEncryptDecryptAlga
  (algaChoice, keyInfo, algorithmMethod, surrenderContext)
AlgaChoice *algaChoice;
POINTER keyInfo;
B_ALGORITHM_METHOD *algorithmMethod;
A_SURRENDER_CTX *surrenderContext;
{
  int status;
  unsigned int contextSize;

  if ((status = (*((A_ENCRYPT_DECRYPT_ALGA *)algorithmMethod->alga)->Query)
       (&contextSize, keyInfo, algaChoice->_algorithmInfo)) != 0)
    return (ConvertAlgaeError (status));

  if ((status = ResizeContextMakeNewContext
       (&algaChoice->context, contextSize)) != 0)
    return (status);

  if ((status = (*((A_ENCRYPT_DECRYPT_ALGA *)algorithmMethod->alga)->Init)
       (algaChoice->context.z.context, keyInfo, algaChoice->_algorithmInfo,
        surrenderContext)) != 0)
    return (ConvertAlgaeError (status));

  return (0);
}
