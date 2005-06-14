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

/* BigUnexp - decrypt ciphertext c into message m using Chinese remainder.
   Assumes m, c of length 2*pSize, pp, qq, dp, dq and cr of length pSize.
   Returns 0, AE_CANCEL.
 */
int BigUnexp (m, c, pp, qq, dp, dq, cr, pSize, surrenderContext)
UINT2 *m;                        /* output message       size 2*pSize words */
UINT2 *c;                              /* input `ciphertext'   size 2*pSize */
UINT2 *pp;                             /* first prime          size pSize   */
UINT2 *qq;                             /* second prime;        size pSize   */
UINT2 *dp;                     /* decryption exponent mod p    size pSize   */
UINT2 *dq;                     /* decryption exponent mod q    size pSize   */
UINT2 *cr;              /* CRT coef (inverse of q mod p) cr has len pSize   */
unsigned int pSize;                                 /* length of p in words */
A_SURRENDER_CTX *surrenderContext;
{
  struct BigUnexpFrame {
    UINT2 t1[2 * MAX_RSA_PRIME_WORDS], t2[2 * MAX_RSA_PRIME_WORDS], 
      t3[2 * MAX_RSA_PRIME_WORDS], u1[2 * MAX_RSA_PRIME_WORDS],
      u2[2 * MAX_RSA_PRIME_WORDS], u3[2 * MAX_RSA_PRIME_WORDS];
  } *frame = (struct BigUnexpFrame *)NULL_PTR;
#if !USE_ALLOCED_FRAME
  struct BigUnexpFrame stackFrame;
#endif
  int status;

  do {
#if USE_ALLOCED_FRAME
    if ((frame = (struct BigUnexpFrame *)T_malloc (sizeof (*frame)))
        == (struct BigUnexpFrame *)NULL_PTR) {
      status = AE_ALLOC;
      break;
    }
#else
    /* Just use the buffers allocated on the stack. */
    frame = &stackFrame;
#endif
    
    BigConst (frame->t1, 0, 2 * pSize);
    BigConst (frame->t2, 0, 2 * pSize);
  
    /* u2=c mod p */
    BigPdiv (frame->u1, frame->u2, c, pp, 2 * pSize, pSize);
    if ((status = CheckSurrender (surrenderContext)) != 0)
      break;

    /* t1=c**dp modP */
    if ((status = BigModExp
         (frame->t1, frame->u2, dp, pp, pSize, surrenderContext)) != 0)
      break;

    /* u3=CmodQ */
    BigPdiv (frame->u2, frame->u3, c, qq, 2 * pSize, pSize);
    if ((status = CheckSurrender (surrenderContext)) != 0)
      break;

    /* t2=c**DQmodQ */
    if ((status = BigModExp
         (frame->t2, frame->u3, dq, qq, pSize, surrenderContext)) != 0)
      break;

    /* CRT.
     */
    BigSub (frame->u1, frame->t1, frame->t2, pSize);

    while (-1 == BigSign (frame->u1, pSize))
      BigAdd (frame->u1, frame->u1, pp, pSize);

    BigMpy (frame->u2, frame->u1, cr, pSize);
    if ((status = CheckSurrender (surrenderContext)) != 0)
      break;
    BigPdiv (frame->u3, frame->u1, frame->u2, pp, 2 * pSize, pSize);
    if ((status = CheckSurrender (surrenderContext)) != 0)
      break;
    BigMpy (m, frame->u1, qq, pSize);

    BigAdd (m, m, frame->t2, 2 * pSize);
  } while (0);
  
  if (frame != (struct BigUnexpFrame *)NULL_PTR) {
    T_memset ((POINTER)frame, 0, sizeof (*frame));
#if USE_ALLOCED_FRAME
    T_free ((POINTER)frame);
#endif
  }
  return (status);
}
