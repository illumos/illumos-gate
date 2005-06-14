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

unsigned int BigLen (a, n)
UINT2 *a;
unsigned int n;
{
  UINT2 signWord = ((a[n-1] & 0x8000) ? ~0 : 0);
  int i, j;
  unsigned int k;

  for (i = n-1; i >= 0 && a[i] == signWord; i--);
  if (i == -1)
    return (1);  /* len of 0 or -1 */

  for (j = 16, k = 0x8000; 
       j >= 0 && 0 == (k & (signWord ^ a[i])); 
       j--, k >>= 1);
  return (16 * i + j);
}
