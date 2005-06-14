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

/* Returns carry: vector a = b * vector c.
 */
UINT2 BigAcc (a, b, c, n)
UINT2 *a;
unsigned int b;
UINT2 *c;
unsigned int n;
{
  UINT4 bTemp, result = (UINT4)0;
  register unsigned int i;

  if (!b)
    return (0);

  bTemp = b;
  for (i = 0; i < n; i++) {
    result += bTemp * ((UINT4) c[i]);
    result += ((UINT4) a[i]);
    a[i] = (UINT2) result;
    result >>= 16;
  }
  return ((UINT2)result);
}
