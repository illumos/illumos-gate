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

/* BigMpy (a, b, c, n) -- a = b * c
     -- assumes b and c have n words, a has 2*n words
     -- inputs may be positive or negative.
 */
void BigMpy (a, b, c, n)
UINT2 *a, *b, *c;
unsigned int n;
{
  UINT2 prod[2 * MAX_RSA_PRIME_WORDS], absb[MAX_RSA_PRIME_WORDS], 
    absc[MAX_RSA_PRIME_WORDS];
  int bSign = BigSign (b, n), cSign = BigSign (c, n);
  
  BigAbs (absb, b, n);
  BigAbs (absc, c, n);
  BigPmpy (prod, absb, absc, n);

  if (bSign * cSign >= 0)
    BigCopy (a, prod, 2 * n);
  else 
    BigNeg (a, prod, 2 * n);

  T_memset ((POINTER)prod, 0, sizeof (prod));
  T_memset ((POINTER)absb, 0, sizeof (absb));
  T_memset ((POINTER)absc, 0, sizeof (absc));
}
