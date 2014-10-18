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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"copysign.S"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(copysign,function)
#include "libm_synonyms.h"

	ENTRY(copysign)
	sethi	%hi(0x80000000),%o3
	andn	%o0,%o3,%o0
	and	%o2,%o3,%o2
	or	%o2,%o0,%o0
	std	%o0,[%sp+0x48]
	retl
	ldd	[%sp+0x48],%f0

	SET_SIZE(copysign)
