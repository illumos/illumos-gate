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

/* BigModx (a, b, c, cInv, n) -- compute a as (b mod c).
     -- assumes a and c of length n, cInv of length n + 2, b of length 2n.
     -- assumes cInv computed with BigInv, and that b < c**2.
 */
void BigModx (a, b, c, cInv, n)
UINT2 *a, *b, *c, *cInv;
unsigned int n;
{
  UINT2 q[MAX_RSA_MODULUS_WORDS];

  BigQrx (q, a, b, c, cInv, n);

  T_memset ((POINTER)q, 0, sizeof (q));
}
