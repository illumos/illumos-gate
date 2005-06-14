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

/* BigAbs (a, b, n) -- a = ABS (b).
 */
void BigAbs (a, b, n)
UINT2 *a, *b;
unsigned int n;
{
  if (BigSign (b, n) >= 0)
    BigCopy (a, b, n); 
  else
    BigNeg (a, b, n);
}
