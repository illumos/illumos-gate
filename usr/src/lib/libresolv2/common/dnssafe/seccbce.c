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

/* On first call, it is assumed that *remainderLen is zero.
   Returns AE_OUTPUT_LEN, 0.
 */
int SecretCBCEncryptUpdate
  (context, xorBlock, remainder, remainderLen, SecretEncrypt, output,
   outputLen, maxOutputLen, input, inputLen)
POINTER context;
unsigned char *xorBlock;
unsigned char *remainder;
unsigned int *remainderLen;
SECRET_CRYPT SecretEncrypt;
unsigned char *output;
unsigned int *outputLen;
unsigned int maxOutputLen;
unsigned char *input;
unsigned int inputLen;
{
  unsigned int partialLen, totalLen, i;

  totalLen = *remainderLen + inputLen;

  /* Output length will be all available 8-byte blocks.
   */
  if ((*outputLen = 8 * (totalLen / 8)) > maxOutputLen)
    return (AE_OUTPUT_LEN);
  
  if (totalLen < 8) {
    /* Not enough to encrypt, just accumulate into remainder.
     */
    T_memcpy
      ((POINTER)remainder + *remainderLen, (POINTER)input, inputLen);
    *remainderLen = totalLen;
    
    return (0);
  }
  
  /* Accumulate enough bytes from input into remainder to encrypt the
       remainder.
   */
  T_memcpy
    ((POINTER)remainder + *remainderLen, (POINTER)input,
     partialLen = 8 - *remainderLen);
    
  for (i = 0; i < 8; i++)
    output[i] = remainder[i] ^ xorBlock[i];
  /* Encrypt in place */
  (*SecretEncrypt) (context, output, output);
  
  T_memcpy ((POINTER)xorBlock, (POINTER)output, 8);
  input += partialLen;
  inputLen -= partialLen;
  output += 8;

  /* Now encrypt the bulk of the input.
   */
  while (inputLen >= 8) {
    for (i = 0; i < 8; i++)
      output[i] = *(input++) ^ xorBlock[i];
    /* Encrypt in place */
    (*SecretEncrypt) (context, output, output);
    T_memcpy ((POINTER)xorBlock, (POINTER)output, 8);
    output += 8;
    inputLen -= 8;
  }

  /* inputLen is now < 8, so copy input to remainder.
   */
  T_memcpy ((POINTER)remainder, (POINTER)input, inputLen);
  *remainderLen = inputLen;
   
  return (0);
}

/* This just ensures that *remainderLen is zero.
   The caller must restart the context (setting remainderLen to zero).
   Returns AE_INPUT_LEN, 0.
 */
int SecretCBCEncryptFinal (remainderLen)
unsigned int remainderLen;
{
  if (remainderLen != 0)
    return (AE_INPUT_LEN);
  
  return (0);
}
