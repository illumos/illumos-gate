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

#ifndef _KAIF_ASMUTIL_H
#define	_KAIF_ASMUTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "mach_asmutil.h"

#ifdef _ASM

/*
 * Each cpusave buffer has an area set aside for a ring buffer of breadcrumbs.
 * The following macros manage the buffer.
 */

/* Advance the ring buffer */
#define	ADVANCE_CRUMB_POINTER(cpusave, tmp1, tmp2) 	\
	ld	[cpusave + KRS_CURCRUMBIDX], tmp1;	\
	cmp	tmp1, KAIF_NCRUMBS - 1;			\
	bge	1f;					\
	/* Advance the pointer and index */		\
	add	tmp1, 1, tmp1;				\
	st	tmp1, [cpusave + KRS_CURCRUMBIDX];	\
	ldx	[cpusave + KRS_CURCRUMB], tmp1;		\
	ba	2f;					\
	add	tmp1, KRM_SIZE, tmp1;			\
1:	/* Reset the pointer and index */		\
	st	%g0, [cpusave + KRS_CURCRUMBIDX];	\
	add	cpusave, KRS_CRUMBS, tmp1;		\
2:	stx	tmp1, [cpusave + KRS_CURCRUMB];		\
	/* Clear the new crumb */			\
	set	KRM_SIZE, tmp2;				\
3:	subcc	tmp2, 8, tmp2;				\
	bg	3b;					\
	stx	%g0, [tmp1 + tmp2]

/* Set a value in the current breadcrumb buffer */
#define	ADD_CRUMB(cpusave, offset, value, tmp) 		\
	ldx	[cpusave + KRS_CURCRUMB], tmp;		\
	stx	value, [tmp + offset];

#define	ADD_CRUMB_CONST(cpusave, offset, value, tmp1, tmp2) \
	ldx	[cpusave + KRS_CURCRUMB], tmp1;		\
	mov	value, tmp2;				\
	stx	tmp2, [tmp1 + offset]

#define	ADD_CRUMB_FLAG(cpusave, flag, tmp1, tmp2, tmp3) \
	ldx	[cpusave + KRS_CURCRUMB], tmp1;		\
	ld	[tmp1 + KRM_FLAG], tmp2;		\
	set	flag, tmp3;				\
	or	tmp2, tmp3, tmp2;			\
	st	tmp2, [tmp1 + KRM_FLAG]

#endif

#ifdef __cplusplus
}
#endif

#endif /* _KAIF_ASMUTIL_H */
