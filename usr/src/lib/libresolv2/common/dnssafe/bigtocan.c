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
#include "port_after.h"


/* BigToCanonical () copies a word vector to a byte vector while REVERSING the
     order of significance.  The word vector is input LSWord first and the
     byte vector is written out MSByte first. It also removes a leading zero
     sign bit. (The byte vector must represent a nonnegative number.)
   Returns 0, AE_DATA.
 */
int BigToCanonical (bytePointer, numBytes, wordPointer, wordCount)
unsigned char *bytePointer;
unsigned int numBytes;
UINT2 *wordPointer;
unsigned int wordCount;
{
  unsigned int copyCount;
  
  if (BigSign (wordPointer, wordCount) < 0 ||
      (BigLen (wordPointer, wordCount) + 7) / 8 > numBytes)
    return (AE_DATA);

  /* start at end of byte vector */
  bytePointer += numBytes-1;
  
  /* copy as much as possible */
  copyCount = (wordCount < numBytes / 2) ? wordCount : numBytes / 2;
  wordCount -= copyCount;
  numBytes -= 2 * copyCount;
  while (copyCount--) {
    /* Copy two bytes.*/
    *bytePointer-- = (unsigned char)*wordPointer;
    *bytePointer-- = (unsigned char)(*wordPointer >> 8);
    wordPointer++;
  }
  
  if (wordCount && numBytes & 1) {
    /* The number of output bytes was odd. Copy one last byte */
    *bytePointer-- = (unsigned char)*wordPointer++;
    wordCount--;
    numBytes--;
  }
  
  /* zero fill remainder of byte vector */
  while (numBytes--)
    *bytePointer-- = 0;
  
  return (0);
}


