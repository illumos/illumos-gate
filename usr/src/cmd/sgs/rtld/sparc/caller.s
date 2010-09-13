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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Return the pc of the calling routine.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if	defined(lint)

#include	<sys/types.h>

caddr_t
caller()
{
	return (0);
}

/* ARGSUSED */
void
set_sparc_g1(ulong_t val)
{
	return;
}

/* ARGSUSED */
void
set_sparc_g2(ulong_t val)
{
	return;
}

/* ARGSUSED */
void
set_sparc_g3(ulong_t val)
{
	return;
}

/* ARGSUSED */
void
set_sparc_g4(ulong_t val)
{
	return;
}

/* ARGSUSED */
void
set_sparc_g5(ulong_t val)
{
	return;
}

/* ARGSUSED */
void
set_sparc_g6(ulong_t val)
{
	return;
}

/* ARGSUSED */
void
set_sparc_g7(ulong_t val)
{
	return;
}
	
#else

#include	<sys/asm_linkage.h>

	.file	"caller.s"

	ENTRY(caller)
	retl
	mov	%i7, %o0
	SET_SIZE(caller)

	ENTRY(set_sparc_g1)
	retl
	mov	%o0, %g1
	SET_SIZE(set_sparc_g1)

	ENTRY(set_sparc_g2)
	retl
	mov	%o0, %g2
	SET_SIZE(set_sparc_g2)

	ENTRY(set_sparc_g3)
	retl
	mov	%o0, %g3
	SET_SIZE(set_sparc_g3)

	ENTRY(set_sparc_g4)
	retl
	mov	%o0, %g4
	SET_SIZE(set_sparc_g4)

	ENTRY(set_sparc_g5)
	retl
	mov	%o0, %g5
	SET_SIZE(set_sparc_g5)
	
	ENTRY(set_sparc_g6)
	retl
	mov	%o0, %g6
	SET_SIZE(set_sparc_g6)

	ENTRY(set_sparc_g7)
	retl
	mov	%o0, %g7
	SET_SIZE(set_sparc_g7)
#endif
