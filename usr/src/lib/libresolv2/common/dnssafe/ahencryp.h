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

#ifndef _AHENCRYP_H_
#define _AHENCRYP_H_ 1

#include "btypechk.h"

/* In C++:
class AHEncryptDecrypt : public B_TypeCheck {
  AHEncryptDecrypt ();
  virtual ~AHEncryptDecrypt () = 0;
  
  virtual int getBlockLen (unsigned int *) = 0;
  virtual int encryptInit
    (B_Key *, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *) = 0;
  virtual int decryptInit
    (B_Key *, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *) = 0;
  virtual int encryptUpdate
    (unsigned char *, unsigned int *, unsigned int, unsigned char *,
     unsigned int, B_Algorithm *, A_SURRENDER_CTX *) = 0;
  virtual int decryptUpdate
    (unsigned char *, unsigned int *, unsigned int, unsigned char *,
     unsigned int, B_Algorithm *, A_SURRENDER_CTX *) = 0;
  virtual int encryptFinal
    (unsigned char *, unsigned int *, unsigned int, B_Algorithm *,
     A_SURRENDER_CTX *) = 0;
  virtual int decryptFinal
    (unsigned char *, unsigned int *, unsigned int, B_Algorithm *,
     A_SURRENDER_CTX *) = 0;
};
 */

/* Use the THIS_ENCRYPT_DECRYPT macro to define the type of object in the
     virtual function prototype.  It defaults to the most base class, but
     derived modules may define the macro to a more derived class before
     including this header file.
 */
#ifndef THIS_ENCRYPT_DECRYPT
#define THIS_ENCRYPT_DECRYPT struct AHEncryptDecrypt
#endif

struct AHEncryptDecrypt;

typedef struct {
  void (*Destructor) PROTO_LIST ((THIS_ENCRYPT_DECRYPT *));
  int (*GetBlockLen) PROTO_LIST ((THIS_ENCRYPT_DECRYPT *, unsigned int *));
  int (*EncryptInit) PROTO_LIST
    ((THIS_ENCRYPT_DECRYPT *, B_Key *, B_ALGORITHM_CHOOSER,
      A_SURRENDER_CTX *));
  int (*DecryptInit) PROTO_LIST
    ((THIS_ENCRYPT_DECRYPT *, B_Key *, B_ALGORITHM_CHOOSER,
      A_SURRENDER_CTX *));
  int (*EncryptUpdate) PROTO_LIST
    ((THIS_ENCRYPT_DECRYPT *, unsigned char *, unsigned int *, unsigned int,
      const unsigned char *, unsigned int, B_Algorithm *, A_SURRENDER_CTX *));
  int (*DecryptUpdate) PROTO_LIST
    ((THIS_ENCRYPT_DECRYPT *, unsigned char *, unsigned int *, unsigned int,
      const unsigned char *, unsigned int, B_Algorithm *, A_SURRENDER_CTX *));
  int (*EncryptFinal) PROTO_LIST
    ((THIS_ENCRYPT_DECRYPT *, unsigned char *, unsigned int *, unsigned int,
      B_Algorithm *, A_SURRENDER_CTX *));
  int (*DecryptFinal) PROTO_LIST
    ((THIS_ENCRYPT_DECRYPT *, unsigned char *, unsigned int *, unsigned int,
      B_Algorithm *, A_SURRENDER_CTX *));
} AHEncryptDecryptVTable;

typedef struct AHEncryptDecrypt {
  B_TypeCheck typeCheck;                                        /* inherited */
  AHEncryptDecryptVTable *vTable;                            /* pure virtual */
} AHEncryptDecrypt;

/* The constructor does not set the vTable since this is a pure base class.
 */
void AHEncryptDecryptConstructor PROTO_LIST ((AHEncryptDecrypt *));
/* No destructor because it is pure virtual. Also, do not call destructor
     for B_TypeCheck, since this will just re-invoke this virtual
     destructor. */

#endif
