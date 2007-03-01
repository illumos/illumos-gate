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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MACH_DOT_H
#define	_MACH_DOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/reg.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if	defined(__sparc)

#define	GETARG0(regset)		regset->lr_rego0
#define	GETARG1(regset)		regset->lr_rego1
#define	GETARG2(regset)		regset->lr_rego2
#define	GETARG3(regset)		regset->lr_rego3
#define	GETARG4(regset)		regset->lr_rego4
#define	GETARG5(regset)		regset->lr_rego5

#define	GETFRAME(regset)	regset->lr_rego6
#define	GETPREVPC(regset)	regset->lr_rego7

#elif	defined(__i386)

#define	GETARG0(regset)		(((ulong_t *)regset->lr_esp)[1])
#define	GETARG1(regset)		(((ulong_t *)regset->lr_esp)[2])
#define	GETARG2(regset)		(((ulong_t *)regset->lr_esp)[3])
#define	GETARG3(regset)		(((ulong_t *)regset->lr_esp)[4])
#define	GETARG4(regset)		(((ulong_t *)regset->lr_esp)[5])
#define	GETARG5(regset)		(((ulong_t *)regset->lr_esp)[6])

#define	GETFRAME(regset)	(regset->lr_ebp)
#define	GETPREVPC(regset)	(*(uintptr_t *)regset->lr_esp)
#elif defined(__amd64)
#define	GETARG0(regset)		regset->lr_rdi
#define	GETARG1(regset)		regset->lr_rsi
#define	GETARG2(regset)		regset->lr_rdx
#define	GETARG3(regset)		regset->lr_rcx
#define	GETARG4(regset)		regset->lr_r8
#define	GETARG5(regset)		regset->lr_r9

#define	GETFRAME(regset)	(regset->lr_rbp)
#define	GETPREVPC(regset)	(*(uintptr_t *)regset->lr_rsp)
#else
#error	unsupported architecture!
#endif


#ifdef	__cplusplus
}
#endif

#endif /* _MACH_DOT_H */
