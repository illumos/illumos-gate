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
struct AHSecretCBCPad;
#define THIS_ENCRYPT_DECRYPT struct AHSecretCBCPad

#include "port_before.h"
#include "global.h"
#include "bsafe2.h"
#include "bkey.h"
#include "balg.h"
#include "ahcbcpad.h"
#include "port_after.h"

#define GENERATE_BREAK(type) { \
    status = type; \
    break; \
  }

/* Inherit the base class destructor, block size,
     and decrypt init and update routines.
 */
static AHEncryptDecryptVTable V_TABLE = {
  AHChooseEncryptDestructor, AHChooseEncryptGetBlockLen,
  AHSecretCBCPadEncryptInit, AHChooseEncryptDecryptInit,
  AHSecretCBCPadEncryptUpdate, AHChooseEncryptDecryptUpdate,
  AHSecretCBCPadEncryptFinal, AHSecretCBCPadDecryptFinal
};

AHSecretCBCPad *AHSecretCBCPadConstructor2 (handler, infoType, info)
AHSecretCBCPad *handler;
struct B_AlgorithmInfoType *infoType;
POINTER info;
{
  if (handler == (AHSecretCBCPad *)NULL_PTR) {
    /* This constructor is being used to do a new */
    if ((handler = (AHSecretCBCPad *)T_malloc (sizeof (*handler)))
        == (AHSecretCBCPad *)NULL_PTR)
      return (handler);
  }

  /* Construct base class with the infoType and info. */
  AHChooseEncryptConstructor2
    (&handler->chooseEncryptDecrypt, infoType, info);

  handler->chooseEncryptDecrypt.encryptDecrypt.vTable = &V_TABLE;
  return (handler);
}

int AHSecretCBCPadEncryptInit (handler, key, chooser, surrenderContext)
AHSecretCBCPad *handler;
B_Key *key;
B_ALGORITHM_CHOOSER chooser;
A_SURRENDER_CTX *surrenderContext;
{
  /* For encryption, we need to track the input length */
  handler->_inputRemainder = 0;

  return (AHChooseEncryptEncryptInit
          (handler, key, chooser, surrenderContext));
}

int AHSecretCBCPadEncryptUpdate
  (handler, partOut, partOutLen, maxPartOutLen, partIn, partInLen,
   randomAlgorithm, surrenderContext)
AHSecretCBCPad *handler;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
const unsigned char *partIn;
unsigned int partInLen;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  /* For encryption, we need to track the input length */
  handler->_inputRemainder = (handler->_inputRemainder + partInLen) % 8;
  
  return (AHChooseEncryptEncryptUpdate
          (handler, partOut, partOutLen, maxPartOutLen, partIn, partInLen,
           randomAlgorithm, surrenderContext));
}

int AHSecretCBCPadEncryptFinal
  (handler, partOut, partOutLen, maxPartOutLen, randomAlgorithm,
   surrenderContext)
AHSecretCBCPad *handler;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;
  unsigned char finalBuffer[8];
  unsigned int padLen, dummyPartOutLen;

  padLen = 8 - handler->_inputRemainder;
  T_memset ((POINTER)finalBuffer, padLen, padLen);

  /* Add the pad bytes.  This should force the output of the final block.
   */
  if ((status = AHChooseEncryptEncryptUpdate
       (handler, partOut, partOutLen, maxPartOutLen, finalBuffer, padLen,
        randomAlgorithm, surrenderContext)) != 0)
    return (status);

  /* The encrypt final operation should have no output. */
  if ((status = AHChooseEncryptEncryptFinal
       (handler, (unsigned char *)NULL_PTR, &dummyPartOutLen, 0,
        (B_Algorithm *)NULL_PTR, (A_SURRENDER_CTX *)NULL_PTR)) != 0)
    return (status);

  /* Restart the context. */
  handler->_inputRemainder = 0;

  /* No need to zeroize the finalBuffer since it only contains pad bytes. */
  return (0);
}

int AHSecretCBCPadDecryptFinal
  (handler, partOut, partOutLen, maxPartOutLen, randomAlgorithm,
   surrenderContext)
AHSecretCBCPad *handler;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;
  unsigned char finalBuffer[16], *padBuffer;
  unsigned int padLen, localPartOutLen, i;
  
  do {
    /* For now, the DecrypyFinal operations is set to output 16 bytes.
     */
    if ((status = AHChooseEncryptDecryptFinal
         (handler, finalBuffer, &localPartOutLen, sizeof (finalBuffer),
          randomAlgorithm, surrenderContext)) != 0)
      break;

    if (localPartOutLen == 8)
      padBuffer = finalBuffer;
    else if (localPartOutLen == 16)
      padBuffer = finalBuffer + 8;
    else
      GENERATE_BREAK (BE_INPUT_LEN);

    /* Check that padding is one 1 to eight 8's.
     */
    if ((padLen = (unsigned int)padBuffer[7]) == 0 || padLen > 8)
      GENERATE_BREAK (BE_INPUT_DATA);
    for (i = 8 - padLen; i < 8; i++) {
      if ((unsigned int)padBuffer[i] != padLen)
        GENERATE_BREAK (BE_INPUT_DATA);
    }

    if ((*partOutLen = localPartOutLen - padLen) > maxPartOutLen)
      GENERATE_BREAK (BE_OUTPUT_LEN);

    T_memcpy
      ((POINTER)partOut, (POINTER)finalBuffer, *partOutLen);
  } while (0);

  T_memset ((POINTER)finalBuffer, 0, sizeof (finalBuffer));
  return (status);
}

