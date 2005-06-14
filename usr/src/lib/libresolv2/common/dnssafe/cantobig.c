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
#include "bigmath.h"
#include "port_after.h"

/* CanonicalToBig () copies a byte vector into a word vector while REVERSING
     the order of significance.  The byte vector is input MSByte first while
     the word vector is written out LSWord first. It also adds a leading zero
     sign bit if necessary.
   Returns 0, AE_DATA.
 */
int CanonicalToBig (wordPointer, wordCount, bytePointer, numBytes)
UINT2 *wordPointer;
unsigned int wordCount;
const unsigned char *bytePointer;
unsigned int numBytes;
{
  unsigned int copyCount;
  
  if (A_IntegerBits (bytePointer, numBytes) / 16 + 1 > wordCount)
    return (AE_DATA);

  /* start at end of byte vector */
  bytePointer += numBytes-1;
  
  /* copy as much as possible */
  copyCount = (wordCount < numBytes / 2) ? wordCount : numBytes / 2;
  wordCount -= copyCount;
  numBytes -= 2 * copyCount;
  while (copyCount--) {
    /* Copy two bytes.*/
    *wordPointer++ = (UINT2)*bytePointer + (*(bytePointer - 1) << 8);
    bytePointer -= 2;
  }
  
  if (wordCount && numBytes & 1) {
    /* If the number of input bytes was odd.  Copy one last byte.*/
    *wordPointer++ = (UINT2)*bytePointer--;
    wordCount--;
    numBytes--;
  }
  
  /* zero fill remainder of word vector */
  while (wordCount--)
    *wordPointer++ = 0;
  
  return (0);
}


