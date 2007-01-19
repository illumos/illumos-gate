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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.
 *	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T
 *	  All Rights Reserved
 */
#if defined(__lint)

#include <sys/link.h>

#include <amd64/amd64.h>

#endif	/* __lint */

#include <sys/asm_linkage.h>
#include <sys/controlregs.h>
#include <sys/trap.h>

#include <amd64/machregs.h>

#include <assym.h>

#ifdef lint
void
amd64_div0trap(void)
{}

void
amd64_dbgtrap(void)
{}

void
amd64_nmiint(void)
{}

void
amd64_brktrap(void)
{}

void
amd64_ovflotrap(void)
{}

void
amd64_boundstrap(void)
{}

void
amd64_invoptrap(void)
{}

void
amd64_ndptrap(void)
{}

void
amd64_doublefault(void)
{}

void
amd64_overrun(void)
{}

void
amd64_invtsstrap(void)
{}

void
amd64_segnptrap(void)
{}

void
amd64_stktrap(void)
{}

void
amd64_gptrap(void)
{}

void
amd64_pftrap(void)
{}

void
amd64_resvtrap(void)
{}

void
amd64_ndperr(void)
{}

void
amd64_achktrap(void)
{}

void
amd64_mcetrap(void)
{}

void
amd64_xmtrap(void)
{}

void
amd64_invaltrap(void)
{}

#else

/*
 * never returns.
 */
#define	TRAP(trapno)		\
	push	$trapno;	\
	jmp	__amd64_exception;

	.text
	.code64

	ENTRY_NP(amd64_div0trap)
	push	$0
	TRAP(T_ZERODIV)		/ $0
	hlt
	SET_SIZE(amd64_div0trap)

	ENTRY_NP(amd64_dbgtrap)
	push	$0
	TRAP(T_SGLSTP)		/ $1
	hlt
	SET_SIZE(amd64_dbgtrap)

	ENTRY_NP(amd64_nmiint)
	push	$0
	TRAP(T_NMIFLT)		/ $2
	hlt
	SET_SIZE(amd64_nmiint)

	ENTRY_NP(amd64_brktrap)
	push	$0
	TRAP(T_BPTFLT)		/ $3
	hlt
	SET_SIZE(amd64_brktrap)

	ENTRY_NP(amd64_ovflotrap)
	push	$0
	TRAP(T_OVFLW)		/ $4
	hlt
	SET_SIZE(amd64_ovflotrap)

	ENTRY_NP(amd64_boundstrap)
	push	$0
	TRAP(T_BOUNDFLT)	/ $5
	hlt
	SET_SIZE(amd64_boundstrap)

	ENTRY_NP(amd64_invoptrap)
	push	$0
	TRAP(T_ILLINST)	/ $6
	hlt
	SET_SIZE(amd64_invoptrap)

	ENTRY_NP(amd64_ndptrap)
	push	$0
	TRAP(T_NOEXTFLT)	/ $7
	hlt
	SET_SIZE(amd64_ndptrap)

	ENTRY_NP(amd64_doublefault)
	push	$0
	TRAP(T_DBLFLT)		/ $8
	hlt
	SET_SIZE(amd64_doublefault)

	ENTRY_NP(amd64_overrun)
	push	$0
	TRAP(T_EXTOVRFLT)	/ $9 i386 only - not generated
	hlt
	SET_SIZE(amd64_overrun)

	ENTRY_NP(amd64_invtsstrap)
	TRAP(T_TSSFLT)	/	$10 already have error code on stack
	hlt
	SET_SIZE(amd64_invtsstrap)

	ENTRY_NP(amd64_segnptrap)
	TRAP(T_SEGFLT)	/	$11 already have error code on stack
	hlt
	SET_SIZE(amd64_segnptrap)

	ENTRY_NP(amd64_stktrap)
	TRAP(T_STKFLT)	/	$12 already have error code on stack
	hlt
	SET_SIZE(amd64_stktrap)

	ENTRY_NP(amd64_gptrap)
	TRAP(T_GPFLT)	/	$13 already have error code on stack
	hlt
	SET_SIZE(amd64_gptrap)

	ENTRY_NP(amd64_pftrap)
	TRAP(T_PGFLT)	/	$14 already have error code on stack
	hlt
	SET_SIZE(amd64_pftrap)

	ENTRY_NP(amd64_resvtrap)
	TRAP(15)		/ (reserved)
	hlt
	SET_SIZE(amd64_resvtrap)

	ENTRY_NP(amd64_ndperr)
	push	$0
	TRAP(T_EXTERRFLT)	/ $16
	hlt
	SET_SIZE(amd64_ndperr)

	ENTRY_NP(amd64_achktrap)
	TRAP(T_ALIGNMENT)	/ $17 zero already on stack
	hlt
	SET_SIZE(amd64_achktrap)

	ENTRY_NP(amd64_mcetrap)
	push	$0
	TRAP(T_MCE)		/ $18
	hlt
	SET_SIZE(amd64_mcetrap)

	ENTRY_NP(amd64_xmtrap)
	push	$0
	TRAP(T_SIMDFPE)	/ $19
	hlt
	SET_SIZE(amd64_xmtrap)

	/*
	 * XX64 if amd64 had sprintf we could do better.
	 */ 
	ENTRY_NP(amd64_invaltrap)
	push	$0
	TRAP(-1)		/ invalid trap
	hlt
	SET_SIZE(amd64_invaltrap)
#endif	/* !__lint */
