/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SHA2_H
#define	_SYS_SHA2_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>		/* for uint_* */

#ifdef	__cplusplus
extern "C" {
#endif

#define	SHA256			0
#define	SHA256_HMAC		1
#define	SHA256_HMAC_GEN		2
#define	SHA384			3
#define	SHA384_HMAC		4
#define	SHA384_HMAC_GEN		5
#define	SHA512			6
#define	SHA512_HMAC		7
#define	SHA512_HMAC_GEN		8

/* SHA2 context. */
typedef struct 	{
	uint32_t algotype;		/* Algorithm Type */

	/* state (ABCDEFGH) */
	union {
		uint32_t s32[8];	/* for SHA256 */
		uint64_t s64[8];	/* for SHA384/512 */
	} state;
	/* number of bits */
	union {
		uint32_t c32[2];	/* for SHA256 , modulo 2^64 */
		uint64_t c64[2];	/* for SHA384/512, modulo 2^128 */
	} count;
	union {
		uint8_t		buf8[128];	/* undigested input */
		uint32_t	buf32[32];	/* realigned input */
		uint64_t	buf64[16];	/* realigned input */
	} buf_un;
} SHA2_CTX;

extern void SHA2Init(uint64_t mech, SHA2_CTX *);

extern void SHA2Update(SHA2_CTX *, const uint8_t *, uint32_t);

extern void SHA2Final(uint8_t *, SHA2_CTX *);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SHA2_H */
