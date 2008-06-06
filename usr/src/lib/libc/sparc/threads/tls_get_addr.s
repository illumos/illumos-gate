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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

	.file	"%M%"

#include "SYS.h"
#include <../assym.h>

/*
 * To make thread-local storage accesses as fast as possible, we
 * hand-craft the __tls_get_addr() function below, from this C code:
 * void *
 * __tls_get_addr(TLS_index *tls_index)
 * {
 *	ulwp_t *self = curthread;
 *	tls_t *tlsent = self->ul_tlsent;
 *	ulong_t moduleid;
 *	caddr_t	base;
 *
 *	if ((moduleid = tls_index->ti_moduleid) < self->ul_ntlsent &&
 *	    (base = tlsent[moduleid].tls_data) != NULL)
 *		return (base + tls_index->ti_tlsoffset);
 *
 *	return (slow_tls_get_addr(tls_index));
 * }
 */

/*
 * We assume that the tls_t structure contains two pointer-sized elements.
 * Cause a build failure if this becomes not true.
 */
#if	SIZEOF_TLS_T == 8 && !defined(__sparcv9)
#define	SHIFT	3
#elif	SIZEOF_TLS_T == 16 && defined(__sparcv9)
#define	SHIFT	4
#else
#error	"Assumption violated: SIZEOF_TLS_T is not 2 * sizeof (uintptr_t)"
#endif

#if	defined(__sparcv9)
#define	PN	,pn %xcc,
#else
#define	PN
#endif

	ENTRY(__tls_get_addr)
	ldn	[%o0 + TI_MODULEID], %o1
	ldn	[%g7 + UL_TLSENT], %o2
	ldn	[%g7 + UL_NTLSENT], %o3
	cmp	%o1, %o3
	bgeu PN	1f
	slln	%o1, SHIFT, %o1
#if TLS_DATA != 0
	add	%o1, TLS_DATA, %o1
#endif
	ldn	[%o1 + %o2], %o2
	cmp	%o2, 0
	be PN	1f
	ldn	[%o0 + TI_TLSOFFSET], %o1
	retl
	add	%o1, %o2, %o0
1:
	mov	%o7, %g1
	call	slow_tls_get_addr
	mov	%g1, %o7
	SET_SIZE(__tls_get_addr)
