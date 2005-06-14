/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.
These notices must be retained in any copies of any part of this
documentation and/or software.
 */

#ifndef _MD5_PRIVATE_H
#define _MD5_PRIVATE_H

#ifdef _SUN_SDK_
#ifndef _MD5_H
#include <md5.h>
#endif /* _MD5_H */

#define _sasl_MD5Init(md5_ctx)	MD5Init(md5_ctx)
#define _sasl_MD5Update(md5_ctx, s, n) MD5Update(md5_ctx, s, n)
#define _sasl_MD5Final(b, md5_ctx) MD5Final(b, md5_ctx)
#else
/* MD5 context. */
typedef struct {
  UINT4 state[4];                                   /* state (ABCD) */
  UINT4 count[2];        /* number of bits, modulo 2^64 (lsb first) */
  unsigned char buffer[64];                         /* input buffer */
} MD5_CTX;

void _sasl_MD5Init PROTO_LIST ((MD5_CTX *));
void _sasl_MD5Update PROTO_LIST
  ((MD5_CTX *, unsigned char *, unsigned int));
void _sasl_MD5Final PROTO_LIST ((unsigned char [16], MD5_CTX *));

void _sasl_hmac_md5 PROTO_LIST ((unsigned char *, int, unsigned char *, int, caddr_t));
#endif /* _SUN_SDK_ */

#endif /* _MD5_PRIVATE_H */
