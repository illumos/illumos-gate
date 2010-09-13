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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DES3_H
#define	_DES3_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	DES3_KEY_SIZE		24
#define	DES3_BLOCK_SIZE		8
#define	DES3_IV_SIZE		8

extern int des3_init(void **);
extern void des3_fini(void *);
extern void des3_encrypt(void *, uint8_t *);
extern void des3_decrypt(void *, uint8_t *);
extern void des3_key(void *, const uint8_t *);
extern boolean_t des3_keycheck(const uint8_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _DES3_H */
