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
#include "surrendr.h"
#include "port_after.h"

/* BigModExp (a, b, c, d, n): a = b**c (mod d)
   Assumes a, b, c, d of length n.
   Returns 0, AE_CANCEL.
 */
int BigModExp (a, b, c, d, n, surrenderContext) 
UINT2 *a, *b, *c, *d;
unsigned int n;
A_SURRENDER_CTX *surrenderContext;
{
  struct BigModExpFrame {
    UINT2 dInv[MAX_RSA_MODULUS_WORDS + 2], result[MAX_RSA_MODULUS_WORDS], 
      tab[16][MAX_RSA_MODULUS_WORDS];
  } *frame = (struct BigModExpFrame *)NULL_PTR;
#if !USE_ALLOCED_FRAME
  struct BigModExpFrame stackFrame;
#endif
  int i, didAMultiply, status;
  unsigned int cLen, w, setup[64], power, mask;

  /* Initialize.
   */
  do {
#if USE_ALLOCED_FRAME
    if ((frame = (struct BigModExpFrame *)T_malloc (sizeof (*frame)))
        == (struct BigModExpFrame *)NULL_PTR) {
      status = AE_ALLOC;
      break;
    }
#else
    /* Just use the buffers allocated on the stack. */
    frame = &stackFrame;
#endif

    /* precompute inverse of d to enable express mod-outs */
    BigInv (frame->dInv, d, n);
    if ((status = CheckSurrender (surrenderContext)) != 0)
      break;
    
    /* precompute small (size 2**w) table of powers of b */
    cLen = BigLen (c, n);
    if (cLen < 4)
      w = 1;
    else if (cLen < 16)
      w = 2;
    else if (cLen < 64)
      w = 3;
    else
      w = 4; 

    /* zeroth power is one */
    BigConst (frame->tab[0], 1, n);

    /* first power is b */
    BigCopy (frame->tab[1], b, n);
    setup[0] = 1;
    setup[1] = 1;
    for (i = 2; i < 64; i++)
      setup[i] = 0;

    /* Loop over elements of exponent c in appropriate radix.
     */
    power = 0;
    didAMultiply = 0;
    mask = 1 << ((cLen) % 16);
    for (i = cLen; i >= 0; i--) {
      if (didAMultiply) {
        BigModSqx (frame->result, frame->result, d, frame->dInv, n);
        if ((status = CheckSurrender (surrenderContext)) != 0)
          break;
      }

      power = power << 1;
      if (setup[power] == 0) {
        BigModSqx (frame->tab[power], frame->tab[power/2], d, frame->dInv, n);
        if ((status = CheckSurrender (surrenderContext)) != 0)
          break;
        setup[power] = 1;
      }
      if (c[i/16] & mask)
        power = power + 1;
      if (mask == 1)
        mask = 0x8000;
      else
        mask = (mask >> 1) & 0x7FFF;
      if (setup[power] == 0) {
        BigModMpyx
          (frame->tab[power], frame->tab[power-1], b, d, frame->dInv, n);
        if ((status = CheckSurrender (surrenderContext)) != 0)
          break;
        setup[power] = 1;
      }
      if ((i == 0) || (power >= (unsigned int)(1 << (w-1)))) {
        if (didAMultiply) {
          BigModMpyx
            (frame->result, frame->result, frame->tab[power], d, frame->dInv,
             n);
          if ((status = CheckSurrender (surrenderContext)) != 0)
            break;
        }
        else
          BigCopy (frame->result, frame->tab[power], n);
      
        power = 0;
        didAMultiply = 1;
      }
    }
    if (status)
      break;

    BigCopy (a, frame->result, n);
  } while (0);

  if (frame != (struct BigModExpFrame *)NULL_PTR) {
    T_memset ((POINTER)frame, 0, sizeof (*frame));
#if USE_ALLOCED_FRAME
    T_free ((POINTER)frame);
#endif
  }
  return (status);
}
