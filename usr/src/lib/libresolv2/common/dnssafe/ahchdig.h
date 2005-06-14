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

#ifndef _AHCHDIG_H_
#define _AHCHDIG_H_ 1

#include "ahdigest.h"
#include "algchoic.h"

typedef struct AHChooseDigest {
  AHDigest digest;                                             /* base class */
  AlgaChoice algaChoice;
} AHChooseDigest;

AHChooseDigest *AHChooseDigestConstructor2 PROTO_LIST
  ((AHChooseDigest *, struct B_AlgorithmInfoType *, POINTER));
void AHChooseDigestDestructor PROTO_LIST ((THIS_DIGEST *));

int AHChooseDigestInit PROTO_LIST
  ((THIS_DIGEST *, B_Key *, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *));
int AHChooseDigestUpdate PROTO_LIST
  ((THIS_DIGEST *, const unsigned char *, unsigned int, A_SURRENDER_CTX *));
int AHChooseDigestFinal PROTO_LIST
  ((THIS_DIGEST *, unsigned char *, unsigned int *, unsigned int,
    A_SURRENDER_CTX *));

#endif
