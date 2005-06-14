/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) RSA Data Security, Inc. created 1994, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

#ifndef _MD5_H_
#define _MD5_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#define A_MD5_DIGEST_LEN 16

#ifndef	SUNW_LIBMD5

typedef struct {
  UINT4 state[4];                                            /* state (ABCD) */
  UINT4 count[2];                 /* number of bits, modulo 2^64 (lsb first) */
  unsigned char buffer[64];                                  /* input buffer */
} A_MD5_CTX;

void A_MD5Init PROTO_LIST ((A_MD5_CTX *));
void A_MD5Update PROTO_LIST ((A_MD5_CTX *, const unsigned char *, unsigned int));
void A_MD5Final PROTO_LIST ((A_MD5_CTX *, unsigned char *));

#else

#include <sys/md5.h>
#define	A_MD5_CTX		MD5_CTX
#define	A_MD5Init(c)		MD5Init((c))
#define	A_MD5Update(c, d, l)	MD5Update((c), (d), (l))
#define	A_MD5Final(c, d)	MD5Final((d), (c))

#endif	/* SUNW_LIBMD5 */

#ifdef __cplusplus
}
#endif

#endif
