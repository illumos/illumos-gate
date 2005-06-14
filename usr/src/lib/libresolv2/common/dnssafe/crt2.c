/*
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#include "crt2.h"
#include "bigmath.h"
#include "port_after.h"

/* RSA encryption/decryption with Chinese Remainder Theorem.
 */

#define GENERATE_BREAK(type) { \
    status = type; \
    break; \
  }

static int RSA_CRT2 PROTO_LIST
  ((A_RSA_CRT2_CTX *, unsigned char *, unsigned int *, unsigned int,
    const unsigned char *, A_SURRENDER_CTX *));

int A_RSA_CRT2Init (context, key)
A_RSA_CRT2_CTX *context;
A_RSA_CRT_KEY *key;
{
  if (A_IntegerBits (key->modulus.data, key->modulus.len)
      > MAX_RSA_MODULUS_BITS)
    /* Key len is too big to handle. */
    return (AE_MODULUS_LEN);

  /* Set the block update blockLen to be big enough to hold the modulus.
   */
  context->blockLen =
    BITS_TO_LEN (A_IntegerBits (key->modulus.data, key->modulus.len));

  context->inputLen = 0;

  /* convert first prime to bignum format */
  if (CanonicalToBig
      (context->primeP, MAX_RSA_PRIME_WORDS, key->prime[0].data,
       key->prime[0].len))
    return (AE_KEY_INFO);
    
  /* compute significant length of first prime */
  context->primeWords = BITS_TO_WORDS
    (BigLen (context->primeP, MAX_RSA_PRIME_WORDS));
    
  /* convert other private key parameters to bignum format */
  if (CanonicalToBig
      (context->primeQ, context->primeWords, key->prime[1].data,
       key->prime[1].len) ||
      CanonicalToBig
      (context->exponentP, context->primeWords,
       key->primeExponent[0].data, key->primeExponent[0].len) ||
      CanonicalToBig
      (context->exponentQ, context->primeWords,
       key->primeExponent[1].data, key->primeExponent[1].len) ||
      CanonicalToBig
      (context->coefficient, context->primeWords,
       key->coefficient.data, key->coefficient.len))
    return (AE_KEY_INFO);

  /* convert modulus to bignum format */
  if (CanonicalToBig
      (context->modulus, 2 * context->primeWords,
       key->modulus.data, key->modulus.len))
    return (AE_KEY_INFO);

  return (0);
}

int A_RSA_CRT2Update
  (context, partOut, partOutLen, maxPartOutLen, partIn, partInLen,
   surrenderContext)
A_RSA_CRT2_CTX *context;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
const unsigned char *partIn;
unsigned int partInLen;
A_SURRENDER_CTX *surrenderContext;
{
  int status;
  unsigned int partialLen, localPartOutLen;

  /* Initialize partOutLen to zero. */
  *partOutLen = 0;

  if (context->inputLen + partInLen < context->blockLen) {
    /* Not enough to encrypt - just accumulate.
     */
    T_memcpy
      ((POINTER)(context->input + context->inputLen), (CPOINTER)partIn,
       partInLen);
    context->inputLen += partInLen;
    return (0);
  }
  
  if (context->inputLen > 0) {
    /* Need to accumulate the rest of the block bytes into the input and
         encrypt from there (otherwise it's OK to encrypt straight from
         the partIn).
     */
    partialLen = context->blockLen - context->inputLen;
    T_memcpy
      ((POINTER)(context->input + context->inputLen), (CPOINTER)partIn,
       partialLen);
    partIn += partialLen;
    partInLen -= partialLen;
    
    if ((status = RSA_CRT2
         (context, partOut, &localPartOutLen, maxPartOutLen, context->input,
          surrenderContext)) != 0)
      return (status);
    (*partOutLen) += localPartOutLen;
    partOut += localPartOutLen;
    maxPartOutLen -= localPartOutLen;
  }

  /* Encrypt as many blocks of input as provided.
   */
  while (partInLen >= context->blockLen) {
    if ((status = RSA_CRT2
         (context, partOut, &localPartOutLen, maxPartOutLen, partIn,
          surrenderContext)) != 0)
      return (status);
    
    partIn += context->blockLen;
    partInLen -= context->blockLen;
    (*partOutLen) += localPartOutLen;
    partOut += localPartOutLen;
    maxPartOutLen -= localPartOutLen;
  }
  
  /* Copy remaining input bytes to the context's input buffer.
   */
  T_memcpy
    ((POINTER)context->input, partIn, partInLen);
  context->inputLen = partInLen;
  return (0);
}

int A_RSA_CRT2Final (context)
A_RSA_CRT2_CTX *context;
{
  if (context->inputLen != 0)
    return (AE_INPUT_LEN);
  
  /* Restart context to accumulate a new block.
   */
  context->inputLen = 0;
  return (0);
}

/* Assume input length is context->blockLen.
 */
static int RSA_CRT2
  (context, output, outputLen, maxOutputLen, input, surrenderContext)
A_RSA_CRT2_CTX *context;
unsigned char *output;
unsigned int *outputLen;
unsigned int maxOutputLen;
const unsigned char *input;
A_SURRENDER_CTX *surrenderContext;
{
  struct ModExpCRTFrame {
    UINT2 bigInBuf[2 * MAX_RSA_PRIME_WORDS],
      bigOutBuf[2 * MAX_RSA_PRIME_WORDS];
  } *frame = (struct ModExpCRTFrame *)NULL_PTR;
#if !USE_ALLOCED_FRAME
  struct ModExpCRTFrame stackFrame;
#endif
  int status;

  status = 0;
  do {
    if ((*outputLen = context->blockLen) > maxOutputLen)
      return (AE_OUTPUT_LEN);
    
#if USE_ALLOCED_FRAME
    if ((frame = (struct ModExpCRTFrame *)T_malloc (sizeof (*frame)))
        == (struct ModExpCRTFrame *)NULL_PTR) {
      status = AE_ALLOC;
      break;
    }
#else
    /* Just use the buffers allocated on the stack. */
    frame = &stackFrame;
#endif

    /* Convert input to bignum representation.
       This won't return AE_DATA since input length was checked at Update.
     */
    CanonicalToBig
      (frame->bigInBuf, 2 * context->primeWords, input, context->blockLen);

    /* Check for overflow. */
    if (BigCmp
        (frame->bigInBuf, context->modulus, 2 * context->primeWords) >= 0)
      GENERATE_BREAK (AE_INPUT_DATA);
    
    /* Chinese remainder exponentiation. */
    if ((status = BigUnexp
         (frame->bigOutBuf, frame->bigInBuf, context->primeP, context->primeQ,
          context->exponentP, context->exponentQ, context->coefficient,
          context->primeWords, surrenderContext)) != 0)
      break;

    /* Convert output to canonical representation.
       This won't return AE_DATA since outputLen was set above.
     */
    BigToCanonical
      (output, *outputLen, frame->bigOutBuf, 2 * context->primeWords);
  } while (0);
  
  if (frame != (struct ModExpCRTFrame *)NULL_PTR) {
    T_memset ((POINTER)frame, 0, sizeof (*frame));
#if USE_ALLOCED_FRAME
    T_free ((POINTER)frame);
#endif
  }
  return (status);
}

