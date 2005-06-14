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

#ifndef _PRIME_H_
#define _PRIME_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

int PrimeFind PROTO_LIST
  ((UINT2 *, unsigned int, unsigned int, UINT2 *, unsigned int,
    unsigned char *, A_SURRENDER_CTX *));
int PseudoPrime PROTO_LIST
  ((unsigned int *, UINT2 *, unsigned int, A_SURRENDER_CTX *));

#ifdef __cplusplus
}
#endif

#endif
