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

/* BigPegcd
     input
     u, v     bignums
     k       int size of u, v regs
     restriction u, v positive
     output
     u3=GCD (u, v)     (pos)
     u1=inv (u)modv   (pos)
     u2=inv (v)modu   (pos)
     if GCD (u, v)!=1 then u1, u2 st
     u3=u * u1mod (v) & u3=v * u2mod (u)
     (see KNUTH vol 2)
 */
void BigPegcd (u3, u1, u2, u, v, k)
UINT2 *u3, *u2, *u1, *u, *v;
unsigned int k;
{
  UINT2 v1[2 * MAX_RSA_PRIME_WORDS], v2[2 * MAX_RSA_PRIME_WORDS], 
    v3[2 * MAX_RSA_PRIME_WORDS], q[2 * MAX_RSA_PRIME_WORDS],
    r[2 * MAX_RSA_PRIME_WORDS], t1[2 * MAX_RSA_PRIME_WORDS],
    t2[2 * MAX_RSA_PRIME_WORDS], t3[2 * MAX_RSA_PRIME_WORDS];

  BigConst (u1, 1, k);
  BigConst (u2, 0, k);
  BigCopy (u3, u, k);
  BigConst (v1, 0, k);
  BigConst (v2, 1, k);
  BigCopy (v3, v, k);

  /* Begin calc.
   */
  while (1) {
    if (BigSign (v3, k) == 0)
      break;
    BigPdiv (q, r, u3, v3, k, k);
    BigPmpyl (t1, v1, q, k);
    BigPmpyl (t2, v2, q, k);
    BigPmpyl (t3, v3, q, k);
    BigSub (t1, u1, t1, k);
    BigSub (t2, u2, t2, k);
    BigSub (t3, u3, t3, k);

    BigCopy (u1, v1, k);
    BigCopy (u2, v2, k);
    BigCopy (u3, v3, k);
    BigCopy (v1, t1, k);
    BigCopy (v2, t2, k);
    BigCopy (v3, t3, k);
  }

  if (BigSign (u1, k) == -1)
    /* make positive */
    BigAdd (u1, u1, v, k);

  if (BigSign (u2, k) == -1)
    /* make positive */
    BigAdd (u2, u2, u, k);

  T_memset ((POINTER)v1, 0, sizeof (v1));
  T_memset ((POINTER)v2, 0, sizeof (v2));
  T_memset ((POINTER)v3, 0, sizeof (v3));
  T_memset ((POINTER)q, 0, sizeof (q));
  T_memset ((POINTER)r, 0, sizeof (r));
  T_memset ((POINTER)t1, 0, sizeof (t1));
  T_memset ((POINTER)t2, 0, sizeof (t2));
  T_memset ((POINTER)t3, 0, sizeof (t3));
}
