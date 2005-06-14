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

/* BigConst (a, v, n) -- a = v, where v is an int.  Initialize bignum a to
     value v.
 */
void BigConst (a, v, n)
UINT2 *a;
unsigned int v;
unsigned int n;
{
  UINT2 signWord = (((UINT2)v & 0x8000) ? ~0 : 0);
  register unsigned int i;

  a[0] = (UINT2)v;
  for (i = 1; i < n; i++)
    a[i] = signWord;
}
