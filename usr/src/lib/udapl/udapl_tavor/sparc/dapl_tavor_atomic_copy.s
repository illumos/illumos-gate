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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#if !defined(__lint)
	.file	"dapl_tavor_atomic_copy.s"
#endif

#include <sys/asm_linkage.h>

#if defined(__lint)

/* ARGSUSED */
void
dapls_atomic_assign_64(uint64_t src, uint64_t *dst)
{}

#else	/* __lint */

	ENTRY(dapls_atomic_assign_64)
	std	%o0, [%o2]
	retl
	nop

	SET_SIZE(dapls_atomic_assign_64)
#endif
