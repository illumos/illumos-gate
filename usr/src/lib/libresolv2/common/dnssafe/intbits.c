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
#include "port_after.h"

/* Return the number of bits in the canonical, positive integer.
   IntgerBits (0) = 0.
 */
unsigned int A_IntegerBits (integer, integerLen)
const unsigned char *integer;
unsigned int integerLen;
{
  unsigned char mask, byte;
  unsigned int bytes, bits;
  
  for (bytes = 0; bytes < integerLen && integer[bytes] == 0; bytes++);
  if (bytes == integerLen)
    return (0);
  
  /* Get byte to test and increment byte count for final calculation */
  byte = integer[bytes++];
  
  /* Get number of bits in most significant byte */
  for (bits = 8, mask = 0x80; (byte & mask) == 0; bits--, mask >>= 1);
  return (8 * (integerLen - bytes) + bits);
}
