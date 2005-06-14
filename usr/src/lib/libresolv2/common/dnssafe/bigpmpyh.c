/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) RSA Data Security, Inc. created 1987, 1996.  This is an
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

/* Returns high order t bytes of result.
 */
void BigPmpyh (a, b, c, t, n)
UINT2 *a, *b, *c;
unsigned int t, n;
{
  register unsigned int i;
  unsigned int iStart, cLen, j;

  BigZero (a, 2*n);
  cLen = BigLenw (c, n);
  iStart = (t >= n-1) ? t - (n-1) : 0;

  for (i = iStart; i < n; i++) {
    j = (t >= i) ? t - i : 0;
    a[cLen+i] = BigAcc
      (&a[i+j], (unsigned int)b[i], &c[j], (cLen >= j) ? cLen-j : 0);
  }
}
