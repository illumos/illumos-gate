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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SOFTRANDOM_H
#define	_SOFTRANDOM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <security/pkcs11t.h>
#include <bignum.h>
#include "softSession.h"

extern int soft_urandom_fd;
extern int soft_urandom_seed_fd;
extern int soft_random_fd;

#define	DEV_URANDOM		"/dev/urandom"
#define	DEV_RANDOM		"/dev/random"

CK_RV soft_random_generator(CK_BYTE *, CK_ULONG, boolean_t);

CK_RV soft_nzero_random_generator(CK_BYTE *, CK_ULONG);

BIG_ERR_CODE random_bignum(BIGNUM *, int, boolean_t);

#ifdef	__cplusplus
}
#endif

#endif /* _SOFTRANDOM_H */
