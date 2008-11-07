/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_COMMON_CRYPTO_FIPS_RANDOM_H
#define	_COMMON_CRYPTO_FIPS_RANDOM_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	SHA1BLOCKBITS		512
#define	SHA1BLOCKBYTES		(SHA1BLOCKBITS >> 3)
#define	SHA1WORDS		5
#define	BYTES_IN_WORD		4
#define	SHA1BYTES		(BYTES_IN_WORD * SHA1WORDS)

extern void fips_random_inner(uint32_t *, uint32_t *, uint32_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _COMMON_CRYPTO_FIPS_RANDOM_H */
