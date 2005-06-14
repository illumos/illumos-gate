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

/* Define this so that the type of the 'this' pointer in the
     virtual functions will be correct for this derived class.
 */
struct AH_RSAEncryption;
#define THIS_ENCRYPT_DECRYPT struct AH_RSAEncryption

#include "port_before.h"
#include "global.h"
#include "bsafe2.h"
#include "bkey.h"
#include "balg.h"
#include "ahrsaenc.h"
#include "port_after.h"

static int AH_RSAEncryptionInitHelper PROTO_LIST ((AH_RSAEncryption *, int));

static AHEncryptDecryptVTable V_TABLE = {
  AH_RSAEncryptionDestructor, AH_RSAEncryptionGetBlockLen,
  AH_RSAEncryptionEncryptInit, AH_RSAEncryptionDecryptInit,
  AH_RSAEncryptionUpdate,
  AH_RSAEncryptionUpdate,
  AH_RSAEncryptionEncryptFinal, AH_RSAEncryptionDecryptFinal
};

void AH_RSAEncryptionConstructor1 (handler, infoType)
AH_RSAEncryption *handler;
struct B_AlgorithmInfoType *infoType;
{
  /* Construct base class with the infoType.  Assume info is NULL_PTR. */
  AHChooseEncryptConstructor2
    (&handler->chooseEncryptDecrypt, infoType, NULL_PTR);

  T_memset ((POINTER)&handler->z, 0, sizeof (handler->z));
  /* Set the AHEncryptDecrypt vTable, but don't set the RSAEncryption vTable
      since it is pure virtual. */
  handler->chooseEncryptDecrypt.encryptDecrypt.vTable = &V_TABLE;
}

void AH_RSAEncryptionDestructor (handler)
AH_RSAEncryption *handler;
{
  T_memset ((POINTER)handler->z.block, 0, handler->z.blockLen);
  T_free ((POINTER)handler->z.block);

  /* Call base class destructor */
  AHChooseEncryptDestructor (handler);
}

int AH_RSAEncryptionGetBlockLen (handler, blockLen)
AH_RSAEncryption *handler;
unsigned int *blockLen;
{
UNUSED_ARG (handler)
UNUSED_ARG (blockLen)
  return (BE_NOT_SUPPORTED);
}

int AH_RSAEncryptionEncryptInit (handler, key, chooser, surrenderContext)
AH_RSAEncryption *handler;
B_Key *key;
B_ALGORITHM_CHOOSER chooser;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = AHChooseEncryptEncryptInit
       (handler, key, chooser, surrenderContext)) != 0)
    return (status);

  return (AH_RSAEncryptionInitHelper (handler, 1));
}

int AH_RSAEncryptionDecryptInit (handler, key, chooser, surrenderContext)
AH_RSAEncryption *handler;
B_Key *key;
B_ALGORITHM_CHOOSER chooser;
A_SURRENDER_CTX *surrenderContext;
{
  int status;

  if ((status = AHChooseEncryptDecryptInit
       (handler, key, chooser, surrenderContext)) != 0)
    return (status);

  return (AH_RSAEncryptionInitHelper (handler, 0));
}

/* Accumulate into the z.block.
 */
int AH_RSAEncryptionUpdate
  (handler, partOut, partOutLen, maxPartOutLen, partIn, partInLen,
   randomAlgorithm, surrenderContext)
AH_RSAEncryption *handler;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
const unsigned char *partIn;
unsigned int partInLen;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
UNUSED_ARG (partOut)
UNUSED_ARG (maxPartOutLen)
UNUSED_ARG (randomAlgorithm)
UNUSED_ARG (surrenderContext)
  *partOutLen = 0;
    
  if (handler->_inputLen + partInLen > handler->_maxInputLen)
    return (BE_INPUT_LEN);
  T_memcpy
    ((POINTER)(handler->z.block + handler->_inputLen), (CPOINTER)partIn,
     partInLen);
  handler->_inputLen += partInLen;
  return (0);
}

int AH_RSAEncryptionEncryptFinal
  (handler, partOut, partOutLen, maxPartOutLen, randomAlgorithm,
   surrenderContext)
AH_RSAEncryption *handler;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  int status;
  unsigned int dummyPartOutLen;
  
  /* Encode methodContext in place. */
  if ((status = (*handler->vTable->EncodeBlock)
       (handler, randomAlgorithm, surrenderContext)) != 0)
    return (status);

  /* This should not return BE_INPUT_DATA since it is well-formatted. */
  if ((status = AHChooseEncryptEncryptUpdate
       (handler, partOut, partOutLen, maxPartOutLen, handler->z.block,
        handler->z.blockLen, (B_Algorithm *)NULL_PTR, surrenderContext)) != 0)
    return (status);

  /* Expect final to return zero bytes. */
  if ((status = AHChooseEncryptEncryptFinal
       (handler, (unsigned char *)NULL_PTR, &dummyPartOutLen, 0,
        (B_Algorithm *)NULL_PTR, surrenderContext)) != 0)
    return (status);
    
  /* Restart the handle for new input. */
  handler->_inputLen = 0;
  return (0);
}

int AH_RSAEncryptionDecryptFinal
  (handler, partOut, partOutLen, maxPartOutLen, randomAlgorithm,
   surrenderContext)
AH_RSAEncryption *handler;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
B_Algorithm *randomAlgorithm;
A_SURRENDER_CTX *surrenderContext;
{
  ITEM output;
  int status;
  unsigned int decryptedLen, dummyPartOutLen;
  
UNUSED_ARG (randomAlgorithm)
  /* Decrypt block in place.  The block lenghts are already within limits.
   */
  if ((status = AHChooseEncryptDecryptUpdate
       (handler, handler->z.block, &decryptedLen, handler->z.blockLen,
        handler->z.block, handler->_inputLen, (B_Algorithm *)NULL_PTR,
        surrenderContext)) != 0)
    return (status);
  /* Expect final to return zero bytes. */
  if ((status = AHChooseEncryptDecryptFinal
       (handler, (unsigned char *)NULL_PTR, &dummyPartOutLen, 0,
        (B_Algorithm *)NULL_PTR, surrenderContext)) != 0)
    return (status);
    
  /* Restart the handle for new input. */
  handler->_inputLen = 0;
      
  /* Now decode the block and copy the result to the partOut.
   */
  if ((status = (*handler->vTable->DecodeBlock)
       (handler, &output, decryptedLen)) != 0)
    return (status);
      
  if (output.len > handler->z.blockLen - 11)
    /* This implies that the block was encrypted with less than
       8 bytes of padding */
    return (BE_INPUT_DATA);
      
  if ((*partOutLen = output.len) > maxPartOutLen)
    return (BE_OUTPUT_LEN);      
  T_memcpy ((POINTER)partOut, (POINTER)output.data, output.len);

  return (0);
}

static int AH_RSAEncryptionInitHelper (handler, encryptFlag)
AH_RSAEncryption *handler;
int encryptFlag;
{
  int status;
  unsigned int newBlockLen;

  if ((status = AHChooseEncryptGetBlockLen (handler, &newBlockLen)) != 0)
    return (status);

  if (newBlockLen < 12)
    /* PKCS Requires at least 12 bytes of modulus */
    return (BE_NOT_SUPPORTED);

  /* During encrypt, this will ensure that there are 8 bytes of padding.
     During decrypt, the DecodeBlock procedure must check that the block
       was encrypted with 8 bytes of padding.
   */
  handler->_maxInputLen = encryptFlag ? (newBlockLen - 11) : newBlockLen;

  handler->_inputLen = 0;
  
  /* Zeroize old block and realloc to new size.
   */
  T_memset ((POINTER)handler->z.block, 0, handler->z.blockLen);
  if ((handler->z.block = (unsigned char *)T_realloc
       ((POINTER)handler->z.block, newBlockLen))
      == (unsigned char *)NULL_PTR) {
    handler->z.blockLen = 0;
    return (BE_ALLOC);
  }
  
  handler->z.blockLen = newBlockLen;
  return (0);
}

