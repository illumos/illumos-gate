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
#include "algae.h"
#include "bigmath.h"
#include "prime.h"
#include "port_after.h"

static unsigned char SMALL_PRIME[]= {3, 5, 7, 11, 13, 17, 19, 23, 29, 31};

/* Prime finding routine.
   Returns 0, AE_CANCEL, AE_NEED_RANDOM.
 */
int PrimeFind
  (prime, primeSizeBits, primeWords, ee, modulusWords, randomBlock,
   surrenderContext)
UINT2 *prime;
unsigned int primeSizeBits;
unsigned int primeWords;
UINT2 *ee;
unsigned int modulusWords;
unsigned char *randomBlock;
A_SURRENDER_CTX *surrenderContext;
{
  UINT2 t1[MAX_RSA_MODULUS_WORDS], u1[MAX_RSA_MODULUS_WORDS],
    u2[MAX_RSA_MODULUS_WORDS], u3[MAX_RSA_MODULUS_WORDS],
    u4[MAX_RSA_MODULUS_WORDS];
  char sieve[1000];
  int status = 0;
  unsigned int i, r, s, testResult;
  
  do {
    /* Create a starting point for the prime from the random block */
    for (i = 0; i < primeWords; i++) {
      prime[i] = (UINT2)((UINT2)randomBlock[0] << 8) + randomBlock[1];
      randomBlock += 2;
    }

    /* set high order two bits */
    BigSetbit (prime, primeSizeBits-2);
    BigSetbit (prime, primeSizeBits-1);   
    for (i = primeSizeBits; i < (unsigned int)(16 * primeWords); i++) 
      BigClrbit (prime, i);

    /* force p to be even */
    BigClrbit (prime, 0);
  
    /* clear sieve and mark even positions */
    for (i = 0; i < 1000; i += 2) {
      sieve[i] = 1;
      sieve[i+1] = 0;
    }

    /* sieve by all odd numbers (don't bother with primality checking) */
    for (s = 3; s < 9000; s += 2) {
      /* increase likelihood that s is prime */
      for (i = 0; i < 5; i++)
        if (s > SMALL_PRIME[i] && !(s % SMALL_PRIME[i]))
          continue;

      /* sieve based on s */
      r = BigSmod (prime, s, primeWords);

      /* returns prime modulo s */
      if (r == 0)
        r = s;

      for (i = s - r; i < 1000; i += s)
        sieve[i] = 1;
    }
  
    /* t1 = 1 */
    BigConst (t1, 1, modulusWords);

    /* now check for primality of values with unmarked sieve */
    testResult = 0;
    for (i = 0; i < 1000; i++, BigInc (prime, primeWords)) {
      if (sieve[i])
        continue;

      /* copy prime into big variable */
      BigZero (u4, modulusWords);
      BigCopy (u4, prime, primeWords);

      /* set u4 = p - 1 */
      BigDec (u4, modulusWords);
      BigPegcd (u1, u2, u3, ee, u4, modulusWords);

      /* Now u1 = gcd (E, t1).
         Test (E, t1)==1 */
      if (BigCmp (t1, u1, modulusWords))
        continue;

      /* check for pseudo primality */
      if ((status = PseudoPrime
           (&testResult, prime, primeWords, surrenderContext)) != 0)
        break;
      if (testResult)
        /* testResult is set and will cause a break out of while (1) loop */
        break;
    }
    if (status)
      break;
    
    if (!testResult)
      /* Couldn't find a prime with the supplied random block, so ask
           caller to generate another random block and try again. */
      status = AE_NEED_RANDOM;
  } while (0);

  T_memset ((POINTER)u1, 0, sizeof (u1));
  T_memset ((POINTER)u2, 0, sizeof (u2));
  T_memset ((POINTER)u3, 0, sizeof (u3));
  T_memset ((POINTER)u4, 0, sizeof (u4));
  return (status);
}

/* Pseudo-primality test.
      If pseudo prime, *testResult = 1, else *testResult = 0.
   Returns 0, AE_CANCEL.
 */
int PseudoPrime (testResult, prime, primeWords, surrenderContext) 
unsigned int *testResult;
UINT2 *prime;
unsigned int primeWords;
A_SURRENDER_CTX *surrenderContext;
{
  UINT2 base[MAX_RSA_MODULUS_WORDS], remainder[MAX_RSA_MODULUS_WORDS];
  int status;
  unsigned int i;

  /* Default testResult to false. */
  *testResult = 0;
  
  /* Prepare for setting base vector to the small prime. */
  T_memset ((POINTER)base, 0, sizeof (base));
  
  for (i = 0; i < 4; i++) {
    /* check to see if target is multiple of SMALL_PRIME */
    if (BigSmod (prime, (unsigned int)SMALL_PRIME[i], primeWords) == 0)
      /* fail... */
      return (0);

    /* Fermat test.  Compute remainder = base ^ prime mod prime
         and compare the base to the remainder.
     */
    base[0] = (UINT2)SMALL_PRIME[i];
    if ((status = BigModExp
         (remainder, base, prime, prime, primeWords, surrenderContext)) != 0)
      return (status);
    if (BigCmp (remainder, base, primeWords) != 0)
      /* fail... */
      return (0);
  }

  *testResult = 1;
  return (0);
}

