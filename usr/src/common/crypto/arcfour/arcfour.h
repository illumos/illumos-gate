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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ARCFOUR_H
#define	_ARCFOUR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/crypto/common.h>

#define	ARCFOUR_MIN_KEY_BYTES	1

#define	ARCFOUR_MAX_KEY_BYTES	256

#define	ARCFOUR_MIN_KEY_BITS	(ARCFOUR_MIN_KEY_BYTES << 3)
#define	ARCFOUR_MAX_KEY_BITS	(ARCFOUR_MAX_KEY_BYTES << 3)

typedef arcfour_state_t ARCFour_key;

void arcfour_key_init(ARCFour_key *key, uchar_t *keyval, int keyvallen);
void arcfour_crypt(ARCFour_key *key, uchar_t *in, uchar_t *out, size_t len);
#ifdef	sun4u
void arcfour_crypt_aligned(ARCFour_key *key, size_t len, uchar_t *in,
    uchar_t *out);
#endif	/* sun4u */

#ifdef	__cplusplus
}
#endif

#endif /* _ARCFOUR_H */
