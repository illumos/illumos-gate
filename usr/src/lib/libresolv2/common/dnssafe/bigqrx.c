/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) RSA Data Security, Inc. created 1990, 1996.  This is an
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


/* BigQrx (q, r, b, c, cInv, n) -- compute quotient and remainder fast.
     -- computes q and r s.t. b = q * c + r with 0 <= r < c.
     -- assumes b and c are positive integers.
     -- assumes q, r, c have n words, cInv has n+2 words, b has 2*n words.
     -- assumes cInv previously computed with BigInv.
 */
void BigQrx (q, r, b, c, cInv, n)
UINT2 *q, *r, *b, *c, *cInv;
unsigned int n;
{
  UINT2 qc[2 * (MAX_RSA_MODULUS_WORDS + 2)],  /* current product of q and c */
    qsc[2 * (MAX_RSA_MODULUS_WORDS + 2)], /* temporary q scaled by 2**(u-s) */
    t1[2 * MAX_RSA_MODULUS_WORDS + 2];
  int uwsw3;
  register unsigned int i;
  unsigned int u, uw, cl, sw;

  /* 2**(cl-1) <= c < 2**cl
     2**(u-cl) <= cInv <= 2**(u-cl+1) */
  cl = BigLen (c, n);
                 
  /* u is in bits, uw is in words */
  u = BigU (2 * cl);
  uw = u/16;
  
  /* sw is in words, s is is bits */
  sw = (cl - 2) / 16;
  
  uwsw3 = uw - sw - 3;
  
  if (uwsw3 < 0)
    uwsw3 = 0;

  /* Copy b to local register.
   */
  BigZero (t1, 2 * n + 2);
  BigCopy (t1, b, 2 * n);

  /* Compute qsc = cInv * floor (b/ (2**s)).
     qsc an approximation to (b/c) * (2**(u-s))
       2**((u-cl)+ (bl-1-s)) <= qsc 2**((u-cl+1)+ (bl-s))
       2**(u-cl+bl-s-1) <= qsc <= 2 ** (u-cl+bl-s+1)
     (Actually, we only compute a "high-order" approximation
       to qsc, by using BigPmpyh.)
   */
  BigPmpyh (qsc, cInv, &t1[sw], uwsw3, n + 2);

  /* Divide by 2**(u-s) to get initial estimate for quotient q
       2**(bl-cl-1) <= q <= 2**(bl-cl+1) (unless q = 0).
   */
  for (i = 0; i < n; i++)
    q[i] = qsc[i+ (uw - sw)];

  /* compute qc = low-order part of q * c
       2 ** (bl - 2) <= qc <= 2 ** (bl + 1) */
  BigPmpyl (qc, q, c, n);

  /* subtract qc from b to get initial estimate for remainder r */
  BigSub (r, b, qc, n);

  /* Adjust to be exactly right by repeated subtraction.
   */
  while (BigCmp (r, c, n) >= 0) {
    BigSub (r, r, c, n);
    BigInc (q, n);
  }
  
  T_memset ((POINTER)qc, 0, sizeof (qc));
  T_memset ((POINTER)qsc, 0, sizeof (qsc));
  T_memset ((POINTER)t1, 0, sizeof (t1));
}


