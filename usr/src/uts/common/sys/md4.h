/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__MD4_H
#define	__MD4_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * MD4C.C - RSA Data Security, Inc., MD4 message-digest algorithm
 */

/*
 * Copyright (C) 1990-2, RSA Data Security, Inc. All rights reserved.
 *
 * License to copy and use this software is granted provided that it
 * is identified as the "RSA Data Security, Inc. MD4 Message-Digest
 * Algorithm" in all material mentioning or referencing this software
 * or this function.
 *
 * License is also granted to make and use derivative works provided
 * that such works are identified as "derived from the RSA Data
 * Security, Inc. MD4 Message-Digest Algorithm" in all material
 * mentioning or referencing the derived work.
 *
 * RSA Data Security, Inc. makes no representations concerning either
 * the merchantability of this software or the suitability of this
 * software for any particular purpose. It is provided "as is"
 * without express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	MD4_DIGEST_LENGTH	16

/* MD4 context. */
typedef struct {
	uint32_t state[4];	/* state (ABCD) */
	uint32_t count[2];	/* number of bits, modulo 2^64 (lsb first) */
	unsigned char buffer[64];	/* input buffer */
} MD4_CTX;

void MD4Init(MD4_CTX *);
void MD4Update(MD4_CTX *, const void *_RESTRICT_KYWD, size_t);
void MD4Final(void *, MD4_CTX *);

#ifdef	__cplusplus
}
#endif

#endif	/* __MD4_H */
