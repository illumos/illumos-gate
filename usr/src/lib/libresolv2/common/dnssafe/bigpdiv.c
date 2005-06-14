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

/* BigPdiv          POSITIVE DIVIDE
     uu=vv * qi+ri
     uu in reg of ll cells
     vv in reg of kk cells
     qi assumed to be ll cells
     ri assumed to be kk cells
     restriction uu>=0, vv>0
       
     input  uu in reg of ll cells
     input  vv in reg of kk cells
     output qi assumed to be ll cells
     output ri assumed to be kk cells
     restriction uu>=0, vv>0
     uu=vv * qi+ri
 */
#define UJN (u[(j+n)/2] & mk[(j+n)%2])
#define VN (v[n/2] & mk[n%2])
#define UT (u[t/2] & mk[t%2])
void BigPdiv (qi, ri, uu, vv, ll, kk)
UINT2 *qi, *ri, *uu, *vv;
unsigned int ll, kk;
{
  UINT2 u[2 * MAX_RSA_PRIME_WORDS + 2], us[2 * MAX_RSA_PRIME_WORDS + 2], 
    v[2 * MAX_RSA_PRIME_WORDS + 2], vs[2 * MAX_RSA_PRIME_WORDS + 2],
    q[2 * MAX_RSA_PRIME_WORDS + 2], r[2 * MAX_RSA_PRIME_WORDS + 2],
    t1[2 * MAX_RSA_PRIME_WORDS + 2], t2[2 * MAX_RSA_PRIME_WORDS + 2],
    t3[2 * MAX_RSA_PRIME_WORDS + 2], mk[2];
  int j, l, n, m, t, x;
  unsigned int a, b, c, d, e, vh, qq;

  if (ll >= kk)
    l = ll + 2;
  else
    l = kk + 2;
  
  mk[0] = 0x00FF;
  mk[1] = 0xFF00;
  b = 0x0100;

  BigConst (u, 0, l);
  BigConst (v, 0, l);
  BigCopy (u, uu, ll);
  BigCopy (us, u, l);
  BigCopy (v, vv, kk);
  BigCopy (vs, v, l);

  /* zero q */
  BigConst (q, 0, l);

  /* Calculate len of v=n.
   */
  for (n = (2 * l) - 1; n >= 0; n--) {
    if (VN == 0)
      continue;
    break;
  }

  /* Normalize.
   */
  a = VN;
  if (n % 2 == 1)
    a = a >> 8;
  d = b / (a+1);
  BigConst (t1, d, l);
  BigPmpyl (t2, t1, v, l);
  BigCopy (v, t2, l);
  
  /* vh=high order digit of normalized v */
  vh = VN;
  if (n % 2 == 1)
    vh = vh >> 8;
  BigPmpyl (t2, t1, u, l);
  BigCopy (u, t2, l);

  /* Calculate len of u=t.
   */
  for (t = (2 * l)-1; t >= 0; t--) {
    if (UT == 0)
      continue;
    break;
  }
  
  /* calc t = n + m */
  m = t - n;

  /* Divide u by v.
   */
  for (j = m + 1 + n; j > n; j--) {
    if (j % 2 == 1)
      c = u[j / 2];
    else {
      a = u[j/2];
      a = a << 8;
      e = u[(j - 1) / 2];
      e = e >> 8;
      c = a + e;
    }
    a = c >> 8;
    if (vh == a)
      qq = b - 1;
    else
      qq = c / vh;

    BigConst (t1, qq, l);
    BigPmpyl (t2, v, t1, l);
    Big2Exp (t3, (j - 1 - n) * 8, l);
    BigPmpyl (t1, t3, t2, l);
    BigSub (t2, u, t1, l);

    /* Adjust q.
     */
    for (x = 0; ; qq --, x ++) {
      if (BigSign (t2, l) != -1)
        break;
      BigPmpyl (t1, t3, v, l);
      BigAdd (t2, t2, t1, l);
    }

    BigCopy (u, t2, l);
    BigConst (t3, qq, l);
    Big2Exp (t2, 8, l);
    BigPmpyl (t1, q, t2, l);
    BigAdd (q, t3, t1, l);
  }
  
  /* Check result.
   */

  BigPmpyl (t1, vs, q, l);
  /* t2 has remainder */
  BigSub (t2, us, t1, l);

  BigSub (t3, vs, t2, l);

  /* transfer results to input registers  */
  BigCopy (qi, q, ll);
  BigCopy (ri, t2, kk);
  
  T_memset ((POINTER)u, 0, sizeof (u));
  T_memset ((POINTER)us, 0, sizeof (us));
  T_memset ((POINTER)v, 0, sizeof (v));
  T_memset ((POINTER)vs, 0, sizeof (vs));
  T_memset ((POINTER)q, 0, sizeof (q));
  T_memset ((POINTER)r, 0, sizeof (r));
  T_memset ((POINTER)t1, 0, sizeof (t1));
  T_memset ((POINTER)t2, 0, sizeof (t2));
  T_memset ((POINTER)t3, 0, sizeof (t3));
}
