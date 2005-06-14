/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) RSA Data Security, Inc. created 1992, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

#include "port_before.h"
#include "global.h"
#include "algae.h"
#include "digrand.h"
#include "port_after.h"

/* Calling routine must initialize the digest algorithm and set
     digestRandom->vTable.
   digestLen is the length of the output of the digest algorithm (i.e. 16).
   state must point to an unsigned char * array of 3 * digestLen.
 */
void A_DigestRandomInit (digestRandom, digestLen, state)
A_DigestRandom *digestRandom;
unsigned int digestLen;
unsigned char *state;
{
  digestRandom->_state = state;
  digestRandom->_output = state + digestLen;
  digestRandom->_digest = digestRandom->_output + digestLen;

  digestRandom->_outputAvailable = 0;
  digestRandom->_digestLen = digestLen;

  T_memset ((POINTER)digestRandom->_state, 0, digestLen);
}

void A_DigestRandomUpdate (digestRandom, input, inputLen)
A_DigestRandom *digestRandom;
unsigned char *input;
unsigned int inputLen;
{
  unsigned int i, j, x;
  
  (*digestRandom->vTable->DigestUpdate) (digestRandom, input, inputLen);
  (*digestRandom->vTable->DigestFinal) (digestRandom, digestRandom->_digest);

  /* add digest to state */
  x = 0;
  for (i = 0; i < digestRandom->_digestLen; i++) {
    j = digestRandom->_digestLen-1-i;
    x += digestRandom->_state[j] + digestRandom->_digest[j];
    digestRandom->_state[j] = (unsigned char)x;
    x >>= 8;
  }
}

void A_DigestRandomGenerateBytes (digestRandom, output, outputLen)
A_DigestRandom *digestRandom;
unsigned char *output;
unsigned int outputLen;
{
  unsigned int available, i;
  
  available = digestRandom->_outputAvailable;

  while (outputLen > available) {
    T_memcpy
      ((POINTER)output,
       (POINTER)&digestRandom->_output[digestRandom->_digestLen-available],
       available);
    output += available;
    outputLen -= available;

    /* generate new output */
    (*digestRandom->vTable->DigestUpdate)
       (digestRandom, digestRandom->_state, digestRandom->_digestLen);
    (*digestRandom->vTable->DigestFinal) (digestRandom, digestRandom->_output);
    available = digestRandom->_digestLen;

    /* increment state */
    for (i = 0; i < digestRandom->_digestLen; i++)
      if (digestRandom->_state[digestRandom->_digestLen-1-i]++)
        break;
  }

  T_memcpy 
    ((POINTER)output,
     (POINTER)&digestRandom->_output[digestRandom->_digestLen-available],
     outputLen);
  digestRandom->_outputAvailable = available - outputLen;
}

