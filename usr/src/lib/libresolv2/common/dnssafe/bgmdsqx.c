/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) RSA Data Security, Inc. created 1986, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

#include "port_before.h"
#include "global.h"
#include "bigmath.h"
#include "port_after.h"

/* BigModSqx (a, b, d, dInv, n) -- a = (b * b) mod d !! EXPRESS.
 */
void BigModSqx (a, b, d, dInv, n)
UINT2 *a, *b, *d, *dInv;
unsigned int n;
{
  UINT2 prod[2 * MAX_RSA_MODULUS_WORDS];

  BigPsq (prod, b, n);
  BigModx (a, prod, d, dInv, n);

  T_memset ((POINTER)prod, 0, sizeof (prod));
}
