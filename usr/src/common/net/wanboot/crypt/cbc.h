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

#ifndef _CBC_H
#define	_CBC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct cbc_handle_s {
	uint32_t keylen;
	uint32_t blocklen;
	uint32_t ivlen;
	void *ks;
	void (*encrypt)(void *, uint8_t *);
	void (*decrypt)(void *, uint8_t *);
} cbc_handle_t;

extern boolean_t cbc_encrypt(cbc_handle_t *ch, uint8_t *data, size_t datalen,
	uint8_t *IV);
extern boolean_t cbc_decrypt(cbc_handle_t *ch, uint8_t *data, size_t datalen,
	uint8_t *IV);
extern void cbc_makehandle(cbc_handle_t *ch, void *cookie, uint32_t keysize,
	uint32_t blocksize, uint32_t ivsize,
	void (*encrypt)(void *, uint8_t *),
	void (*decrypt)(void *, uint8_t *));

#ifdef	__cplusplus
}
#endif

#endif /* _CBC_H */
