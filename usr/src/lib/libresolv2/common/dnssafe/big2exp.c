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

/* Big2Exp (a, v, n) -- a = 2**v, where v is nonnegative int.  
   Sets a to be 2**v.
 */
void Big2Exp (a, v, n)
UINT2 *a;
unsigned v;
unsigned int n;
{
  register unsigned int i;

  for (i = 0; i < n; i++)
    a[i] = 0;
  a[v/16] = 1 << (v % 16);
}
