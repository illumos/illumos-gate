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

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/psw.h>

#if defined(__lint)
#include <sys/types.h>
#include <sys/segments.h>
#endif

#if defined(__lint)

ulong_t
kdi_getdr0(void)
{
	return (0);
}

ulong_t
kdi_getdr1(void)
{
	return (0);
}

ulong_t
kdi_getdr2(void)
{
	return (0);
}

ulong_t
kdi_getdr3(void)
{
	return (0);
}

ulong_t
kdi_getdr6(void)
{
	return (0);
}

ulong_t
kdi_getdr7(void)
{
	return (0);
}

/*ARGSUSED*/
void
kdi_setdr0(ulong_t value)
{}

/*ARGSUSED*/
void
kdi_setdr1(ulong_t value)
{}

/*ARGSUSED*/
void
kdi_setdr2(ulong_t value)
{}

/*ARGSUSED*/
void
kdi_setdr3(ulong_t value)
{}

/*ARGSUSED*/
void
kdi_setdr4(ulong_t value)
{}

/*ARGSUSED*/
void
kdi_setdr6(ulong_t value)
{}

/*ARGSUSED*/
void
kdi_setdr7(ulong_t value)
{}

#else

#if defined(__amd64)

#define	GETDREG(name, r)	\
	ENTRY_NP(name);		\
	movq	r, %rax;	\
	ret;			\
	SET_SIZE(name)

#define	SETDREG(name, r)	\
	ENTRY_NP(name);		\
	movq	%rdi, r;	\
	ret;			\
	SET_SIZE(name)

#elif defined(__i386)

#define	GETDREG(name, r)	\
	ENTRY_NP(name);		\
	movl	r, %eax;	\
	ret;			\
	SET_SIZE(name)

#define	SETDREG(name, r)	\
	ENTRY_NP(name);		\
	movl	4(%esp), %eax;	\
	movl	%eax, r;	\
	ret;			\
	SET_SIZE(name)

#endif

	GETDREG(kdi_getdr0, %dr0)
	GETDREG(kdi_getdr1, %dr1)
	GETDREG(kdi_getdr2, %dr2)
	GETDREG(kdi_getdr3, %dr3)
	GETDREG(kdi_getdr6, %dr6)
	GETDREG(kdi_getdr7, %dr7)

	SETDREG(kdi_setdr0, %dr0)
	SETDREG(kdi_setdr1, %dr1)
	SETDREG(kdi_setdr2, %dr2)
	SETDREG(kdi_setdr3, %dr3)
	SETDREG(kdi_setdr6, %dr6)
	SETDREG(kdi_setdr7, %dr7)

#endif	/* __lint */
