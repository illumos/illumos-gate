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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright (c) 1996-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_PROF_H
#define	_PROF_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	MARK
#define	MARK(K)	{}
#else
#undef	MARK

#if defined(__i386)
#define	MARK(K)	{\
		asm("	.data"); \
		asm("	.align 4"); \
		asm("."#K".:"); \
		asm("	.long 0"); \
		asm("	.text"); \
		asm("M."#K":"); \
		asm("	movl	$."#K"., %edx"); \
		asm("	call _mcount"); \
		}
#endif

#if defined(__sparc)
#define	MARK(K)	{\
		asm("	.reserve	."#K"., 4, \".bss\", 4"); \
		asm("M."#K":"); \
		asm("	sethi	%hi(."#K".), %o0"); \
		asm("	call	_mcount"); \
		asm("	or	%o0, %lo(."#K".), %o0"); \
		}
#endif

#endif	/* MARK */

#ifdef	__cplusplus
}
#endif

#endif	/* _PROF_H */
