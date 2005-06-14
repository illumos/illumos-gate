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

#ifndef _AHCHENCR_H_
#define _AHCHENCR_H_ 1

#include "ahencryp.h"
#include "algchoic.h"

/* In C++:
class AHChooseEncryptDecrypt : public AHEncryptDecrypt {
public:
  AHChooseEncryptDecrypt (B_AlgorithmInfoType *, POINTER);
  virtual ~AHChooseEncryptDecrypt () {};

  virtual int getBlockLen (unsigned int *);
  virtual int encryptInit (B_Key *, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *);
  virtual int decryptInit (B_Key *, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *);
  virtual int encryptUpdate
    (unsigned char *, unsigned int *, unsigned int, unsigned char *,
     unsigned int, B_Algorithm *, A_SURRENDER_CTX *);
  virtual int decryptUpdate
    (unsigned char *, unsigned int *, unsigned int, unsigned char *,
     unsigned int, B_Algorithm *, A_SURRENDER_CTX *);
  virtual int encryptFinal
    (unsigned char *, unsigned int *, unsigned int, B_Algorithm *,
     A_SURRENDER_CTX *);
  virtual int decryptFinal
    (unsigned char *, unsigned int *, unsigned int, B_Algorithm *,
     A_SURRENDER_CTX *);

private:
  AlgaChoice algaChoice;
};
 */

typedef struct AHChooseEncryptDecrypt {
  AHEncryptDecrypt encryptDecrypt;                             /* base class */
  AlgaChoice algaChoice;
} AHChooseEncryptDecrypt;

AHChooseEncryptDecrypt *AHChooseEncryptConstructor2 PROTO_LIST
  ((AHChooseEncryptDecrypt *, struct B_AlgorithmInfoType *, POINTER));
void AHChooseEncryptDestructor PROTO_LIST ((THIS_ENCRYPT_DECRYPT *));

int AHChooseEncryptGetBlockLen PROTO_LIST
  ((THIS_ENCRYPT_DECRYPT *, unsigned int *));
int AHChooseEncryptEncryptInit PROTO_LIST
  ((THIS_ENCRYPT_DECRYPT *, B_Key *, B_ALGORITHM_CHOOSER,
    A_SURRENDER_CTX *));
int AHChooseEncryptDecryptInit PROTO_LIST
  ((THIS_ENCRYPT_DECRYPT *, B_Key *, B_ALGORITHM_CHOOSER,
    A_SURRENDER_CTX *));
int AHChooseEncryptEncryptUpdate PROTO_LIST
  ((THIS_ENCRYPT_DECRYPT *, unsigned char *, unsigned int *,
    unsigned int, const unsigned char *, unsigned int, B_Algorithm *,
    A_SURRENDER_CTX *));
int AHChooseEncryptDecryptUpdate PROTO_LIST
  ((THIS_ENCRYPT_DECRYPT *, unsigned char *, unsigned int *,
    unsigned int, const unsigned char *, unsigned int, B_Algorithm *,
    A_SURRENDER_CTX *));
int AHChooseEncryptEncryptFinal PROTO_LIST
  ((THIS_ENCRYPT_DECRYPT *, unsigned char *, unsigned int *,
    unsigned int, B_Algorithm *, A_SURRENDER_CTX *));
int AHChooseEncryptDecryptFinal PROTO_LIST
  ((THIS_ENCRYPT_DECRYPT *, unsigned char *, unsigned int *,
    unsigned int, B_Algorithm *, A_SURRENDER_CTX *));

#endif
