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

#ifndef _AHCHRAND_H_
#define _AHCHRAND_H_ 1

#include "ahrandom.h"
#include "algchoic.h"

typedef struct AHChooseRandom {
  AHRandom random;                                             /* base class */
  AlgaChoice algaChoice;
} AHChooseRandom;

AHChooseRandom *AHChooseRandomConstructor2 PROTO_LIST
  ((AHChooseRandom *, struct B_AlgorithmInfoType *, POINTER));
void AHChooseRandomDestructor PROTO_LIST ((THIS_RANDOM *));

int AHChooseRandomInit PROTO_LIST
  ((THIS_RANDOM *, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *));
int AHChooseRandomUpdate PROTO_LIST
  ((THIS_RANDOM *, unsigned char *, unsigned int, A_SURRENDER_CTX *));
int AHChooseRandomGenerateBytes PROTO_LIST
  ((THIS_RANDOM *, unsigned char *, unsigned int, A_SURRENDER_CTX *));

#endif
