/*
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) RSA Data Security, Inc. created 1992, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

#ifndef _BIGMATH_H_
#define _BIGMATH_H_ 1

#include "algae.h"
#include "bigmaxes.h"

#ifdef __cplusplus
extern "C" {
#endif

void Big2Exp PROTO_LIST ((UINT2 *, unsigned int, unsigned int));
void BigAbs PROTO_LIST ((UINT2 *, UINT2 *, unsigned int));
UINT2 BigAcc PROTO_LIST ((UINT2 *, unsigned int, UINT2 *, unsigned int));
void BigZero PROTO_LIST ((UINT2 *, unsigned int));
void BigAdd PROTO_LIST ((UINT2 *, UINT2 *, UINT2 *, unsigned int));
void BigSub PROTO_LIST ((UINT2 *, UINT2 *, UINT2 *, unsigned int));
void BigNeg PROTO_LIST ((UINT2 *, UINT2 *, unsigned int));
void BigInc PROTO_LIST ((UINT2 *, unsigned int));
void BigDec PROTO_LIST ((UINT2 *, unsigned int));
int BigSign PROTO_LIST ((UINT2 *, unsigned int));
void BigCopy PROTO_LIST ((UINT2 *, UINT2 *, unsigned int));
unsigned int BigLenw PROTO_LIST ((UINT2 *, unsigned int));
void BigClrbit PROTO_LIST ((UINT2 *, unsigned int));
void BigSetbit PROTO_LIST ((UINT2 *, unsigned int));
int BigCmp PROTO_LIST ((UINT2 *, UINT2 *, unsigned int));
void BigConst PROTO_LIST ((UINT2 *, unsigned int, unsigned int));
void BigInv PROTO_LIST ((UINT2 *, UINT2 *, unsigned int));
unsigned int BigLen PROTO_LIST ((UINT2 *, unsigned int));
void BigModMpyx PROTO_LIST
  ((UINT2 *, UINT2 *, UINT2 *, UINT2 *, UINT2 *, unsigned int));
void BigModSqx PROTO_LIST
  ((UINT2 *, UINT2 *, UINT2 *, UINT2 *, unsigned int));
int BigModExp PROTO_LIST
  ((UINT2 *, UINT2 *, UINT2 *, UINT2 *, unsigned int, A_SURRENDER_CTX *));
void BigModx PROTO_LIST
  ((UINT2 *, UINT2 *, UINT2 *, UINT2 *, unsigned int));
void BigMpy PROTO_LIST ((UINT2 *, UINT2 *, UINT2 *, unsigned int));
void BigPdiv PROTO_LIST
  ((UINT2 *, UINT2 *, UINT2 *, UINT2 *, unsigned int , unsigned int));
void BigPegcd PROTO_LIST
  ((UINT2 *, UINT2 *, UINT2 *, UINT2 *, UINT2 *, unsigned int));
void BigPmpy PROTO_LIST ((UINT2 *, UINT2 *, UINT2 *, unsigned int));
void BigPmpyh PROTO_LIST
  ((UINT2 *, UINT2 *, UINT2 *, unsigned int, unsigned int));
void BigPmpyl PROTO_LIST ((UINT2 *, UINT2 *, UINT2 *, unsigned int));
void BigPsq PROTO_LIST ((UINT2 *, UINT2 *, unsigned int));
void BigQrx PROTO_LIST
  ((UINT2 *, UINT2 *, UINT2 *, UINT2 *, UINT2 *, unsigned int));
UINT2 BigSmod PROTO_LIST ((UINT2 *, unsigned int, unsigned int));
int BigToCanonical PROTO_LIST
  ((unsigned char *, unsigned int, UINT2 *, unsigned int));
unsigned int BigU PROTO_LIST ((unsigned int));
int BigUnexp PROTO_LIST
  ((UINT2 *, UINT2 *, UINT2 *, UINT2 *, UINT2 *, UINT2 *, UINT2 *,
    unsigned int, A_SURRENDER_CTX *));
int CanonicalToBig PROTO_LIST
  ((UINT2 *, unsigned int, const unsigned char *, unsigned int));

#ifdef __cplusplus
}
#endif

#endif
