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

/* Similar to BigPmpy (a, b, b, n) but faster.
 */
void BigPsq (a, b, n)
UINT2 *a, *b;
unsigned int n;
{
  UINT4 result = (UINT4)0;
  register unsigned int i;
  unsigned int bLen;

  BigZero (a, 2*n);
  bLen = BigLenw (b, n);
  if (!bLen)
    return;

  for (i = 0; i < bLen-1; i++)
    a[bLen+i] = BigAcc (&a[2*i+1], (unsigned int)b[i], &b[i+1], bLen-i-1);
  BigAdd (a, a, a, 2*n);

  /* add in trace b[i] * b[i] */
  for (i = 0; i < bLen; i++) {
    result += ((UINT4)b[i]) * ((UINT4)b[i]);
    result += (UINT4)a[2*i];
    a[2*i] = (UINT2)result;
    result >>= 16;
    result += (UINT4)a[2*i+1];
    a[2*i+1] = (UINT2)result;
    result >>= 16;
  }
  a[2*i] = (UINT2)result;
}
