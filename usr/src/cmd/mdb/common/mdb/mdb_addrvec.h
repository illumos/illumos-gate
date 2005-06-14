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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_MDB_ADDRVEC_H
#define	_MDB_ADDRVEC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct mdb_addrvec {
	uintptr_t *ad_data;		/* Array of addresses */
	size_t ad_nelems;		/* Number of valid elements */
	size_t ad_size;			/* Array size */
	size_t ad_ndx;			/* Array index */
} mdb_addrvec_t;

#ifdef _MDB

extern void mdb_addrvec_create(mdb_addrvec_t *);
extern void mdb_addrvec_destroy(mdb_addrvec_t *);

extern uintptr_t mdb_addrvec_shift(mdb_addrvec_t *);
extern void mdb_addrvec_unshift(mdb_addrvec_t *, uintptr_t);
extern size_t mdb_addrvec_length(mdb_addrvec_t *);

#endif	/* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_ADDRVEC_H */
