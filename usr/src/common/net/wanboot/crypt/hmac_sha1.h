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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _HMAC_SHA1_H
#define	_HMAC_SHA1_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sha1.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	HMAC_DIGEST_LEN	20

extern void HMACInit(SHA1_CTX *, const uchar_t *, size_t);
extern void HMACUpdate(SHA1_CTX *, const uchar_t *, size_t);
extern void HMACFinal(SHA1_CTX *sha1Context, const uchar_t *, size_t,
    uchar_t digest[HMAC_DIGEST_LEN]);


#ifdef	__cplusplus
}
#endif

#endif /* _HMAC_SHA1_H */
