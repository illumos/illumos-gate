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

#ifndef _AHRSAENC_H_
#define _AHRSAENC_H_

#include "ahchencr.h"

struct AH_RSAEncryption;

/* For EncodeBlock, the block to encode is left justified in the
     z.block with length given by z._inputLen.  EncodeBlock encodes the block
     in place to fill it out to z.blockLen.
   For DecodeBlock, return the contents in the given ITEM by decoding
     the z.block value which has length given by decryptedLen.  This
     procedure must also ensure that the block was encrypted with 8 bytes
     of padding.
 */
typedef struct {
  int (*EncodeBlock) PROTO_LIST
    ((THIS_ENCRYPT_DECRYPT *, B_Algorithm * /* randomAlgorithm */,
      A_SURRENDER_CTX *));
  int (*DecodeBlock) PROTO_LIST
    ((THIS_ENCRYPT_DECRYPT *, ITEM *, unsigned int /* decryptedLen */));
} AH_RSAEncryptionVTable;

typedef struct AH_RSAEncryption {
  AHChooseEncryptDecrypt chooseEncryptDecrypt;                 /* base class */

  struct {
    unsigned char *block;
    unsigned int blockLen;
  } z;                                            /* Zeroized by constructor */

  unsigned int _inputLen;            /* Length of data accumulated by Update */
  unsigned int _maxInputLen;     /* used during update to check for overflow */
  AH_RSAEncryptionVTable *vTable;                            /* pure virtual */
} AH_RSAEncryption;

void AH_RSAEncryptionConstructor1 PROTO_LIST
  ((AH_RSAEncryption *, struct B_AlgorithmInfoType *));
void AH_RSAEncryptionDestructor PROTO_LIST ((AH_RSAEncryption *));

int AH_RSAEncryptionGetBlockLen PROTO_LIST
  ((THIS_ENCRYPT_DECRYPT *, unsigned int *));
int AH_RSAEncryptionEncryptInit PROTO_LIST
  ((THIS_ENCRYPT_DECRYPT *, B_Key *, B_ALGORITHM_CHOOSER,
    A_SURRENDER_CTX *));
int AH_RSAEncryptionDecryptInit PROTO_LIST
  ((THIS_ENCRYPT_DECRYPT *, B_Key *, B_ALGORITHM_CHOOSER,
    A_SURRENDER_CTX *));
int AH_RSAEncryptionUpdate PROTO_LIST
  ((THIS_ENCRYPT_DECRYPT *, unsigned char *, unsigned int *,
    unsigned int, const unsigned char *, unsigned int, B_Algorithm *,
    A_SURRENDER_CTX *));
int AH_RSAEncryptionEncryptFinal PROTO_LIST
  ((THIS_ENCRYPT_DECRYPT *, unsigned char *, unsigned int *,
    unsigned int, B_Algorithm *, A_SURRENDER_CTX *));
int AH_RSAEncryptionDecryptFinal PROTO_LIST
  ((THIS_ENCRYPT_DECRYPT *, unsigned char *, unsigned int *,
    unsigned int, B_Algorithm *, A_SURRENDER_CTX *));

#endif
