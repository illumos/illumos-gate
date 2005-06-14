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

static unsigned int Log2 PROTO_LIST ((unsigned int));

/* BigInv (a, b, n) -- compute a as an "inverse" to b, suitable for
     modding out integers which are < b**2.
     -- assumes a has n+2 words, b has n words.
     -- assumes b is a positive integer.
 */              
void BigInv (a, b, n)
UINT2 *a, *b;
unsigned int n;
{
  UINT2 p[2 * (MAX_RSA_MODULUS_WORDS + 2)],
    q[2 * (MAX_RSA_MODULUS_WORDS + 3)], t1[MAX_RSA_MODULUS_WORDS + 3];
  register int i;
  unsigned int bl, u, uw, sw;

  /* Do initializations.
   */
  /* 2** (bl-1) <= b < 2 ** bl */
  bl = BigLen (b, n);
  u = BigU (2 * bl);
  
  /* uw and sw are in words */
  uw = u/16;
  sw = (bl - 2) / 16;
  
  /* since a = floor ((2**u)/b),  2**(u-bl) < a <= 2**(u-bl+1) */

  /* Initialize a to 1+2**(u-bl) -- we will converge from below.
   */
  Big2Exp (a, u - bl, n + 2);
  BigInc (a, n + 2);
  
  /* Copy b to local register.
   */
  BigZero (t1, n + 3);
  BigCopy (t1, b, n);

  /* Convergence is quadratic, so iterate log (len (a)) times.
   */
  for (i = 1 + Log2 (u - bl + 1); i > 0; i--) {
    /* use fast squaring routine to compute p = a**2
       2**(2 * (u-bl)) < p <= 2**(2 * (u-bl+1)) */
    BigPsq (p, a, n + 2); 

    /* compute q = b * floor (p/ (2**s))
       2**(2 * (u-bl)-s+bl-1) <= q <= 2**(2 * (u-bl+1)-s+bl
       2**(2 * u-bl-s-1) <= q <= 2**(2 * u-bl-s+2) */
    BigPmpy (q, t1, &p[sw], n + 3);

    /* double a
       2**(u-bl+1) < a <= 2**(u-bl+2) */
    BigAdd (a, a, a, n + 2);
    /* a = a - floor (q/(2**(u-s)))
       2**(u-bl) < a <= 2**(u-bl+1) + epsilon */
    BigSub (a, a, &q[uw-sw], n + 2);
  }

  /* now we are guaranteed that a is not too small */
  BigInc (a, n + 2);

  while (1) {
    BigPmpy (p, a, t1, n + 2);
    /* makes comparison to 2**u easier */
    BigDec (p, 2 * (n + 2));

    /* a is desired result */
    if (BigLen (p, 2 * (n + 2)) <= u)
      break;

    /* a was too big, reduce and try again */
    BigDec (a, n + 2);
  }

  T_memset ((POINTER)p, 0, sizeof (p));
  T_memset ((POINTER)q, 0, sizeof (q));
  T_memset ((POINTER)t1, 0, sizeof (t1));
}

/* Log2 (x) -- ceiling of log base 2 of x > 0. Auxiliary function.
 */
static unsigned int Log2 (x)
unsigned int x;
{
  unsigned int i;

  x = x - 1;
  /* now Log2 is equal to len in bits of x */
  for (i = 0; x > 0; i++, x >>= 1);

  return (i);
}
