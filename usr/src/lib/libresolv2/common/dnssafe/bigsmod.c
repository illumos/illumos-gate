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

UINT2 BigSmod (a, v, n)
UINT2 *a;
unsigned int v;
unsigned int n;
{
  UINT4 r = (UINT4)0;
  register int i;
  unsigned int scale;

  scale = (unsigned int)((UINT4)65536 % (UINT4)v);

  for (i = n-1; i >= 0; i--) {
    r = (r*scale) + (UINT4)a[i];
    r = r % (UINT4)v;
  }
  return ((UINT2)r);
}
