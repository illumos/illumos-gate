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
#include "secrcbc.h"
#include "port_after.h"

static void SecretCBCDecryptBlock PROTO_LIST
  ((POINTER, unsigned char *, SECRET_CRYPT, unsigned char *,
    unsigned char *));

/* On first call, it is assumed that *remainderLen is zero.
   This assumes remainder buffer is at least 16 bytes is size.
   Returns AE_OUTPUT_LEN, 0.
 */
int SecretCBCDecryptUpdate
  (context, xorBlock, remainder, remainderLen, SecretDecrypt, output,
   outputLen, maxOutputLen, input, inputLen)
POINTER context;
unsigned char *xorBlock;
unsigned char *remainder;
unsigned int *remainderLen;
SECRET_CRYPT SecretDecrypt;
unsigned char *output;
unsigned int *outputLen;
unsigned int maxOutputLen;
unsigned char *input;
unsigned int inputLen;
{
  unsigned int partialLen;

  if (*remainderLen + inputLen <= 16) {
    /* Not enough to decrypt, just accumulate into remainder.
     */
    *outputLen = 0;
    T_memcpy ((POINTER)remainder + *remainderLen, (POINTER)input, inputLen);
    *remainderLen += inputLen;
    return (0);
  }

  /* Fill up the rest of the remainder with bytes from input.
   */
  T_memcpy
    ((POINTER)remainder + *remainderLen, (POINTER)input,
     partialLen = 16 - *remainderLen);
  input += partialLen;
  inputLen -= partialLen;    

  /* remainder is full and inputLen is at least 1.  Compute outputLen
       as the size needed to keep remainder as full as possible.
   */
  if ((*outputLen = 8 * ((inputLen + 7) / 8)) > maxOutputLen)
    return (AE_OUTPUT_LEN);

  SecretCBCDecryptBlock
    (context, xorBlock, SecretDecrypt, output, remainder);
  output += 8;
  
  if (inputLen <= 8) {
    /* Shift remaining input bytes into remainder */
    T_memmove ((POINTER)remainder, (POINTER)(remainder + 8), 8);
    T_memcpy ((POINTER)(remainder + 8), (POINTER)input, inputLen);
    *remainderLen = 8 + inputLen;
    return (0);
  }

  /* Decrypt the rest of the remainder.
   */
  SecretCBCDecryptBlock
    (context, xorBlock, SecretDecrypt, output, remainder + 8);
  output += 8;

  /* Now decrypt the bulk of the input.
   */
  while (inputLen > 16) {
    SecretCBCDecryptBlock (context, xorBlock, SecretDecrypt, output, input);
    output += 8;
    input += 8;
    inputLen -= 8;
  }

  /* inputLen is now <= 16, so copy input to remainder.
   */
  T_memcpy ((POINTER)remainder, (POINTER)input, inputLen);
  *remainderLen = inputLen;
  return (0);
}

/* The caller must restart the context (setting remainderLen to zero).
   Returns AE_INPUT_LEN, AE_OUTPUT_LEN, 0.
 */
int SecretCBCDecryptFinal
  (context, xorBlock, remainder, remainderLen, SecretDecrypt, output,
   outputLen, maxOutputLen)
POINTER context;
unsigned char *xorBlock;
unsigned char *remainder;
unsigned int remainderLen;
SECRET_CRYPT SecretDecrypt;
unsigned char *output;
unsigned int *outputLen;
unsigned int maxOutputLen;
{
  if ((*outputLen = remainderLen) == 0)
    /* There was never any data. */
    return (0);
  
  if (remainderLen != 8 && remainderLen != 16)
    return (AE_INPUT_LEN);

  if (*outputLen > maxOutputLen)
    return (AE_OUTPUT_LEN);

  SecretCBCDecryptBlock
    (context, xorBlock, SecretDecrypt, output, remainder);
  output += 8;
  if (remainderLen == 16)
    SecretCBCDecryptBlock
      (context, xorBlock, SecretDecrypt, output, remainder + 8);
  return (0);
}

static void SecretCBCDecryptBlock (context, xorBlock, SecretDecrypt, out, in)
POINTER context;
unsigned char *xorBlock;
SECRET_CRYPT SecretDecrypt;
unsigned char *out;
unsigned char *in;
{
  unsigned char tempBuffer[8];
  unsigned int i;
  
  /* Save input to be copied to the xor block. */
  T_memcpy ((POINTER)tempBuffer, (POINTER)in, 8);
  (*SecretDecrypt) (context, out, in);
  for (i = 0; i < 8; i++)
    out[i] ^= xorBlock[i];  
  T_memcpy ((POINTER)xorBlock, (POINTER)tempBuffer, 8);
  
  T_memset ((POINTER)tempBuffer, 0, sizeof (tempBuffer));
}
