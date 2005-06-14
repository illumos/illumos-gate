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
#include "port_after.h"

/* BigU (t) -- returns length u where floor (2**u/b) is used as scaled version
     of (1/b) when modding out modulo b, and where (positive) integers to be
     reduced are < 2**t; i.e. they are at most t bits in length.
   Result is (t+1) rounded up if necessary to next multiple of 16.
*/
unsigned int BigU (t)
unsigned int t;
{
  return (16 * (((t+1) + 15)/16)); 
}
