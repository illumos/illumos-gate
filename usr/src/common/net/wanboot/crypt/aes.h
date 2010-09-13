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

#ifndef _AES_H
#define	_AES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	AES_256_KEY_SIZE	32
#define	AES_192_KEY_SIZE	24
#define	AES_128_KEY_SIZE	16
#define	AES_BLOCK_SIZE		16
#define	AES_IV_SIZE		16

extern int aes_init(void **);
extern void aes_fini(void *);
extern void aes_encrypt(void *, uint8_t *);
extern void aes_decrypt(void *, uint8_t *);
extern void aes_key(void *, const uint8_t *, uint32_t);
extern boolean_t aes_keycheck(const uint8_t *, uint32_t);

#ifdef	__cplusplus
}
#endif

#endif /* _AES_H */
