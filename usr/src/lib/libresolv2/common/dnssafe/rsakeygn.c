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
#include "surrendr.h"
#include "prime.h"
#include "rsakeygn.h"
#include "port_after.h"

#define GENERATE_BREAK(type) { \
    status = type; \
    break; \
  }

static int RSAParameters PROTO_LIST
  ((UINT2 *, UINT2 *, UINT2 *, UINT2 *, UINT2 *, UINT2 *, UINT2 *, UINT2 *,
    unsigned int, unsigned int, A_SURRENDER_CTX *));
static void SetRSAKeyGenResult PROTO_LIST
  ((A_PKCS_RSA_PRIVATE_KEY *, A_RSA_KEY_GEN_CTX *, UINT2 *, UINT2 *));

int A_RSAKeyGenInit (context, params)
A_RSA_KEY_GEN_CTX *context;
A_RSA_KEY_GEN_PARAMS *params;
{
  context->modulusBits = params->modulusBits;
  
  /* Prezeroize big public exponent vector. */
  T_memset
    ((POINTER)context->bigPublicExponent, 0,
     sizeof (context->bigPublicExponent));
    
  /* Copy public exponent into big vector */
  if (CanonicalToBig
      (context->bigPublicExponent, MAX_RSA_MODULUS_WORDS,
       params->publicExponent.data, params->publicExponent.len) != 0)
    /* could not copy exponent into MAX_RSA_MODULUS_WORDS */
    return (AE_EXPONENT_LEN);

  /* Check that public exponent is in bounds and odd.
   */
  if (BigLen (context->bigPublicExponent, MAX_RSA_MODULUS_WORDS) >=
      context->modulusBits)
    return (AE_EXPONENT_LEN);
  if (!(context->bigPublicExponent[0] & 1))
    return (AE_EXPONENT_EVEN);

  return (0);
}

/* This generates an RSA keypair of size modulusBits with the fixed
     publicExponent, pointing result to the resulting integers.  The
     resulting integer data is in the context, so that the values must be
     copied before the context is zeroized.
   All integers are unsigned canonical bytes arrays with the most significant
     byte first.
   The randomBlock is of length randomBlockLen returned by RSAKeyGenQuery.
   This assumes that the modulusBits size was checked by RSAKeyGenQuery.
 */
int A_RSAKeyGen (context, result, randomBlock, surrenderContext)
A_RSA_KEY_GEN_CTX  *context;
A_PKCS_RSA_PRIVATE_KEY **result;
unsigned char *randomBlock;
A_SURRENDER_CTX *surrenderContext;
{
  UINT2 *bigPrimeP, *bigPrimeQ;
  int status;
  unsigned int modulusWords, primeSizeBits, primeWords;

  /* Prezeroize all big word vectors. */
  T_memset ((POINTER)context->bigModulus, 0, sizeof (context->bigModulus));
  T_memset
    ((POINTER)context->bigPrivateExponent, 0,
     sizeof (context->bigPrivateExponent));
  T_memset ((POINTER)context->bigPrime1, 0, sizeof (context->bigPrime1));
  T_memset ((POINTER)context->bigPrime2, 0, sizeof (context->bigPrime2));
  T_memset ((POINTER)context->bigExponentP, 0, sizeof (context->bigExponentP));
  T_memset ((POINTER)context->bigExponentQ, 0, sizeof (context->bigExponentQ));
  T_memset
    ((POINTER)context->bigCoefficient, 0, sizeof (context->bigCoefficient));

  /* prime size is half modulus size */
  modulusWords = BITS_TO_WORDS (context->modulusBits);
  primeSizeBits = RSA_PRIME_BITS (context->modulusBits);
  primeWords = BITS_TO_WORDS (RSA_PRIME_BITS (context->modulusBits));
    
  /* Fish for bigPrime1 and bigPrime2 that are compatible with supplied
       publicExponent.
     The randomBlock holds random bytes for two primes.
   */
  if ((status = PrimeFind
       (context->bigPrime1, primeSizeBits, primeWords,
        context->bigPublicExponent, modulusWords, randomBlock,
        surrenderContext)) != 0)
    return (status);
  if ((status = PrimeFind
       (context->bigPrime2, context->modulusBits - primeSizeBits,
        primeWords, context->bigPublicExponent, modulusWords,
        randomBlock + (2 * primeWords), surrenderContext)) != 0)
    return (status);

  /* Set bigPrimeP to the larger of bigPrime1 and bigPrime2 and set
       bigPrimeQ to the smaller.
   */
  if (BigCmp (context->bigPrime1, context->bigPrime2, primeWords) == 1) {
    bigPrimeP = context->bigPrime1;
    bigPrimeQ = context->bigPrime2;
  }
  else {
    bigPrimeP = context->bigPrime2;
    bigPrimeQ = context->bigPrime1;
  }

  /* Calculate the rest of the key components */
  if ((status = RSAParameters 
       (context->bigModulus, context->bigCoefficient,
        context->bigExponentP, context->bigExponentQ,
        context->bigPrivateExponent, context->bigPublicExponent,
        bigPrimeP, bigPrimeQ, primeWords, modulusWords, surrenderContext)) != 0)
    return (status);
    
  /* Copy key components into canonical buffers which are at the
       end of the context. */
  *result = &context->result;
  SetRSAKeyGenResult (*result, context, bigPrimeP, bigPrimeQ);
  
  return (0);
}

/* Assumes ee, pp, qq are given, calculates other parameters.
   Returns 0, AE_CANCEL.
 */
static int RSAParameters 
  (nn, cr, dp, dq, dd, ee, pp, qq, primeWords, modulusWords, surrenderContext)
UINT2 *nn, *cr, *dp, *dq, *dd, *ee, *pp, *qq;
unsigned int primeWords, modulusWords;
A_SURRENDER_CTX *surrenderContext;
{
  UINT2 t1[2 * MAX_RSA_PRIME_WORDS], t2[MAX_RSA_PRIME_WORDS],
    t3[MAX_RSA_MODULUS_WORDS], u1[MAX_RSA_MODULUS_WORDS],
    u3[MAX_RSA_MODULUS_WORDS], pm1[MAX_RSA_PRIME_WORDS], 
    qm1[MAX_RSA_PRIME_WORDS];
  int status;
  
  do {
    /* N=P*Q */
    BigMpy (t1, pp, qq, primeWords);
    if ((status = CheckSurrender (surrenderContext)) != 0)
      break;
    BigCopy (nn, t1, modulusWords);
  
    /*  qm1=q-1 & pm1=p-1 */
    BigConst (t1, 1, primeWords);
    BigSub (qm1, qq, t1, primeWords);
    BigSub (pm1, pp, t1, primeWords);
    
    /* t3=1 */
    BigConst (t3, 1, modulusWords);
  
    /*t1=phi (N) */
    BigMpy (t1, pm1, qm1, primeWords);
    if ((status = CheckSurrender (surrenderContext)) != 0)
      break;

    /* compute decryption exponent */
    BigPegcd (u1, dd, u3, ee, t1, modulusWords);
    if ((status = CheckSurrender (surrenderContext)) != 0)
      break;

    /* calc DP=inv (E)[mod (P-1)] & DQ=inv (e)[mod (Q-1)] */
    BigPdiv (t1, dp, dd, pm1, modulusWords, primeWords);
    if ((status = CheckSurrender (surrenderContext)) != 0)
      break;
    BigPdiv (t1, dq, dd, qm1, modulusWords, primeWords);
    if ((status = CheckSurrender (surrenderContext)) != 0)
      break;
  
    /* calc CR = (inv (Q)[modP]) */
    BigPegcd (t1, t2, cr, pp, qq, primeWords);
  } while (0);
  
  T_memset ((POINTER)t1, 0, sizeof (t1));
  T_memset ((POINTER)t2, 0, sizeof (t2));
  T_memset ((POINTER)t3, 0, sizeof (t3));
  T_memset ((POINTER)u1, 0, sizeof (u1));
  T_memset ((POINTER)u3, 0, sizeof (u3));
  T_memset ((POINTER)pm1, 0, sizeof (pm1));
  T_memset ((POINTER)qm1, 0, sizeof (qm1));
  return (status);
}

static void SetRSAKeyGenResult (result, context, bigPrimeP, bigPrimeQ)
A_PKCS_RSA_PRIVATE_KEY *result;
A_RSA_KEY_GEN_CTX *context;
UINT2 *bigPrimeP;
UINT2 *bigPrimeQ;
{
  unsigned int primeLen, modulusLen;

  modulusLen = result->modulus.len = result->publicExponent.len =
    result->privateExponent.len = BITS_TO_LEN (context->modulusBits);
  primeLen = result->prime[0].len = result->prime[1].len = 
    result->primeExponent[0].len = result->primeExponent[1].len =
    result->coefficient.len = RSA_PRIME_LEN (context->modulusBits);
  
  result->modulus.data = context->resultBuffer;
  result->publicExponent.data = result->modulus.data + modulusLen;
  result->privateExponent.data = result->publicExponent.data + modulusLen;
  result->prime[0].data = result->privateExponent.data + modulusLen;
  result->prime[1].data = result->prime[0].data + primeLen;
  result->primeExponent[0].data = result->prime[1].data + primeLen;
  result->primeExponent[1].data = result->primeExponent[0].data + primeLen;
  result->coefficient.data = result->primeExponent[1].data + primeLen;

  BigToCanonical
    (result->modulus.data, modulusLen, context->bigModulus,
     MAX_RSA_MODULUS_WORDS);
  BigToCanonical
    (result->publicExponent.data, modulusLen,
     context->bigPublicExponent, MAX_RSA_MODULUS_WORDS);
  BigToCanonical
    (result->privateExponent.data, modulusLen,
     context->bigPrivateExponent, MAX_RSA_MODULUS_WORDS);
  BigToCanonical 
    (result->prime[0].data, primeLen, bigPrimeP, MAX_RSA_PRIME_WORDS);
  BigToCanonical 
    (result->prime[1].data, primeLen, bigPrimeQ, MAX_RSA_PRIME_WORDS);
  BigToCanonical 
    (result->primeExponent[0].data, primeLen, context->bigExponentP,
     MAX_RSA_PRIME_WORDS);
  BigToCanonical
    (result->primeExponent[1].data, primeLen, context->bigExponentQ,
     MAX_RSA_PRIME_WORDS);
  BigToCanonical
    (result->coefficient.data, primeLen, context->bigCoefficient,
     MAX_RSA_PRIME_WORDS);
}
