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

#ifndef _AHCHGEN_H_
#define _AHCHGEN_H_ 1

#include "ahgen.h"
#include "algchoic.h"

/* Make a new class derived from an AlgaChoice which records the
     result algorithm info type and needed randomBlockLen.
 */
typedef struct GenerateAlgaChoice {
  AlgaChoice algaChoice;                                       /* base class */

  struct B_KeyInfoType *_resultInfoType;
  ResizeContext secondContext;                           /* used for scratch */
  ResizeContext randomBlock;
  unsigned int _randomBlockLen;
} GenerateAlgaChoice;

typedef struct AHChooseGenerate {
  AHGenerate generate;                                         /* base class */

  GenerateAlgaChoice generateAlgaChoice;
} AHChooseGenerate;

AHChooseGenerate *AHChooseGenerateConstructor2 PROTO_LIST
  ((AHChooseGenerate *, struct B_AlgorithmInfoType *, POINTER));
void AHChooseGenerateDestructor PROTO_LIST ((THIS_GENERATE *));

int AHChooseGenerateInit PROTO_LIST
  ((THIS_GENERATE *, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *));
int AHChooseGenerateKeypair PROTO_LIST
  ((THIS_GENERATE *, B_Key *, B_Key *, B_Algorithm *, A_SURRENDER_CTX *));
int AHChooseGenerateParameters PROTO_LIST
  ((THIS_GENERATE *, B_Algorithm *, B_Algorithm *, A_SURRENDER_CTX *));

#endif
