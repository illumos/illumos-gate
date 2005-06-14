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

#ifndef _BALG_H_
#define _BALG_H_ 1

#include "binfocsh.h"
#include "btypechk.h"

typedef struct {
  B_InfoCache infoCache;                                        /* inherited */

  struct {
    B_TypeCheck *handler;
    int initFlag;
    /* POINTER reserved; */
  } z;
} B_Algorithm;

void B_AlgorithmConstructor PROTO_LIST ((B_Algorithm *));
void B_AlgorithmDestructor PROTO_LIST ((B_Algorithm *));

int B_AlgorithmCheckType PROTO_LIST ((B_Algorithm *, B_TYPE_CHECK_DESTRUCTOR));
int B_AlgorithmCheckTypeAndInitFlag PROTO_LIST
  ((B_Algorithm *, B_TYPE_CHECK_DESTRUCTOR));

struct B_AlgorithmInfoType;
int B_AlgorithmSetInfo PROTO_LIST
  ((B_Algorithm *, struct B_AlgorithmInfoType *, POINTER));
int B_AlgorithmGetInfo PROTO_LIST
  ((B_Algorithm *, POINTER *, struct B_AlgorithmInfoType *));

int B_AlgorithmRandomInit PROTO_LIST
  ((B_Algorithm *, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *));
int B_AlgorithmRandomUpdate PROTO_LIST
  ((B_Algorithm *, unsigned char *, unsigned int, A_SURRENDER_CTX *));
int B_AlgorithmGenerateRandomBytes PROTO_LIST
  ((B_Algorithm *, unsigned char *, unsigned int, A_SURRENDER_CTX *));

int B_AlgorithmDigestInit PROTO_LIST
  ((B_Algorithm *, B_Key *, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *));
int B_AlgorithmDigestUpdate PROTO_LIST
  ((B_Algorithm *, const unsigned char *, unsigned int, A_SURRENDER_CTX *));
int B_AlgorithmDigestFinal PROTO_LIST
  ((B_Algorithm *, unsigned char *, unsigned int *, unsigned int,
    A_SURRENDER_CTX *));

int B_AlgorithmEncryptInit PROTO_LIST
  ((B_Algorithm *, B_Key *, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *));
int B_AlgorithmDecryptInit PROTO_LIST
  ((B_Algorithm *, B_Key *, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *));
int B_AlgorithmEncryptUpdate PROTO_LIST
  ((B_Algorithm *, unsigned char *, unsigned int *, unsigned int,
    unsigned char *, unsigned int, B_Algorithm *, A_SURRENDER_CTX *));
int B_AlgorithmDecryptUpdate PROTO_LIST
  ((B_Algorithm *, unsigned char *, unsigned int *, unsigned int,
    const unsigned char *, unsigned int, B_Algorithm *, A_SURRENDER_CTX *));
int B_AlgorithmEncryptFinal PROTO_LIST
  ((B_Algorithm *, unsigned char *, unsigned int *, unsigned int,
    B_Algorithm *, A_SURRENDER_CTX *));
int B_AlgorithmDecryptFinal PROTO_LIST
  ((B_Algorithm *, unsigned char *, unsigned int *, unsigned int,
    B_Algorithm *, A_SURRENDER_CTX *));

int B_AlgorithmEncodeInit PROTO_LIST ((B_Algorithm *));
int B_AlgorithmDecodeInit PROTO_LIST ((B_Algorithm *));
int B_AlgorithmEncodeUpdate PROTO_LIST
  ((B_Algorithm *, unsigned char *, unsigned int *, unsigned int,
    unsigned char *, unsigned int));
int B_AlgorithmDecodeUpdate PROTO_LIST
  ((B_Algorithm *, unsigned char *, unsigned int *, unsigned int,
    unsigned char *, unsigned int));
int B_AlgorithmEncodeFinal PROTO_LIST
  ((B_Algorithm *, unsigned char *, unsigned int *, unsigned int));
int B_AlgorithmDecodeFinal PROTO_LIST
  ((B_Algorithm *, unsigned char *, unsigned int *, unsigned int));

int B_AlgorithmSignInit PROTO_LIST
  ((B_Algorithm *, B_Key *, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *));
int B_AlgorithmSignUpdate PROTO_LIST
  ((B_Algorithm *, unsigned char *, unsigned int, A_SURRENDER_CTX *));
int B_AlgorithmSignFinal PROTO_LIST
  ((B_Algorithm *, unsigned char *, unsigned int *, unsigned int,
    B_Algorithm *, A_SURRENDER_CTX *));

int B_AlgorithmVerifyInit PROTO_LIST
  ((B_Algorithm *, B_Key *, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *));
int B_AlgorithmVerifyUpdate PROTO_LIST
  ((B_Algorithm *, unsigned char *, unsigned int, A_SURRENDER_CTX *));
int B_AlgorithmVerifyFinal PROTO_LIST
  ((B_Algorithm *, unsigned char *, unsigned int, B_Algorithm *,
    A_SURRENDER_CTX *));

int B_AlgorithmKeyAgreeInit PROTO_LIST
  ((B_Algorithm *, B_Key *, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *));
int B_AlgorithmKeyAgreePhase1 PROTO_LIST
  ((B_Algorithm *, unsigned char *, unsigned int *, unsigned int,
    B_Algorithm *, A_SURRENDER_CTX *));
int B_AlgorithmKeyAgreePhase2 PROTO_LIST
  ((B_Algorithm *, unsigned char *, unsigned int *, unsigned int,
    unsigned char *, unsigned int, A_SURRENDER_CTX *));

int B_AlgorithmGenerateInit PROTO_LIST
  ((B_Algorithm *, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *));
int B_AlgorithmGenerateKeypair PROTO_LIST
  ((B_Algorithm *, B_Key *, B_Key *, B_Algorithm *,
    A_SURRENDER_CTX *));
int B_AlgorithmGenerateParameters PROTO_LIST
  ((B_Algorithm *, B_Algorithm *, B_Algorithm *, A_SURRENDER_CTX *));

#endif
