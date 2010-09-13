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

.ident	"%Z%%M%	%I%	%E% SMI"

/*
 * cerror() for system calls that return 64-bit values.
 */

	.file	"cerror64.s"

#include "SYS.h"

	ENTRY2(_cerror64,__cerror64)
	cmp	%o0, ERESTART
	be,a	1f
	mov	EINTR, %o0
1:
	save	%sp, -SA(MINFRAME), %sp
	call	___errno
	nop
	st	%i0, [%o0]
	restore
	mov	-1, %o1
	retl
	mov	-1, %o0

	SET_SIZE(_cerror64)
	SET_SIZE(__cerror64)
