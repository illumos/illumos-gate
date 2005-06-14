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

void BigZero (a, n)
UINT2 *a;
unsigned int n;
{
  register unsigned int i;
  
  for (i = 0; i < n; i++)
    a[i] = 0;
}

void BigAdd (a, b, c, n)
UINT2 *a, *b, *c;
unsigned int n;
{
  UINT4 result = (UINT4)0;
  register unsigned int i;

  for (i = 0; i < n; i++) {
    result += (UINT4) b[i];
    result += (UINT4) c[i];
    a[i] = (UINT2) result;
    result >>= 16;
  }
}

void BigSub (a, b, c, n)
UINT2 *a, *b, *c;
unsigned int n;
{
  UINT4 result = (UINT4)1;                   /* carry bit for negation of c */
  register unsigned int i;

  for (i = 0; i < n; i++) {
    result += (UINT4) b[i];
    result += (((UINT4) ~c[i]) & 0x0000FFFFL);
    a[i] = (UINT2)result;
    result >>= 16;
  }
}

void BigNeg (a, b, n)
UINT2 *a, *b;
unsigned int n;
{
  register unsigned int i;
  unsigned int carry = 1;

  for (i = 0; i < n-1; i++) {
    a[i] = ~b[i] + carry;
    if (a[i])
      carry = 0;
  }
  
  a[i] = ~b[i] + carry;
}

void BigInc (a, n)
UINT2 *a;
unsigned int n;
{
  register unsigned int i;
  unsigned int carry = 1;                                 /* carry to start */

  for (i = 0; i < n-1 && carry; i++) {
    a[i]++;
    if (a[i])
      carry = 0;
  }
  
  if (carry)
    a[i]++;
}

void BigDec (a, n)
UINT2 *a;
unsigned int n;
{
  register unsigned int i;
  unsigned int borrow = 1;                               /* borrow to start */

  for (i = 0; i < n-1 && borrow; i++) {
    a[i]--;
    if (a[i] != 0xFFFF)
      borrow = 0;
  }
  
  if (borrow)
    a[i]--;
}

int BigSign (a, n)
UINT2 *a;
unsigned int n;
{
  register int i;
  
  if (a[n-1] & 0x8000)
    return (-1);
  for (i = n-1; i >= 0; i--)
    if (a[i])
      return (1);
  return (0);
}

void BigCopy (a, b, n)
UINT2 *a, *b;
unsigned int n;
{
  register unsigned int i;
  
  for (i = 0; i < n; i++)
    a[i] = b[i];
}

/* Assumes a is nonnegative.
 */
unsigned int BigLenw (a, n)
UINT2 *a;
unsigned int n;
{
  register int i;
  
  for (i = n-1; i >= 0; i--)
    if (a[i])
      return (i+1);
  return (0);
}
