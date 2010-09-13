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
!
!	"@(#)SYS.h 1.14 88/02/08"
!       Copyright (c) 1986, 1996 by Sun Microsystems, Inc.
!	All rights reserved.
!

#include <sys/syscall.h>
#include <machine/asm_linkage.h>
#include "PIC.h"

#define SV_ERESTART	91	/* ERESTART is returned by the kernel for
				   restartable system calls */

#define WINDOWSIZE	(16*4)

	.global	.cerror

#define SYSCALL(x) \
	ENTRY(x); \
	mov	SYS_/**/x, %g1; \
	t	8; \
	CERROR(o5)

#define BSDSYSCALL(x) \
	ENTRY(_/**/x); \
	mov	SYS_/**/x, %g1; \
	t	8; \
	CERROR(o5)

/*
 * SYSREENTRY provides the entry sequence for restartable system calls.
 */
#define SYSREENTRY(x)	\
	ENTRY(x);	\
	st      %o0,[%sp+68]; \
.restart_/**/x:

#define PSEUDO(x, y) \
	ENTRY(x); \
	mov	SYS_/**/y, %g1; \
	t	8;

/*
 * SYSCALL_RESTART provides the most common restartable system call sequence.
 */
#define SYSCALL_RESTART(x) \
	SYSREENTRY(x); \
	mov	SYS_/**/x, %g1; \
	t	8; \
	SYSRESTART(.restart_/**/x)

/*
 * SYSREENTRY provides the entry sequence for restartable system calls.
 */
#define SYSREENTRY(x) \
	ENTRY(x); \
	st      %o0,[%sp+68]; \
.restart_/**/x:

/*
 * SYSRESTART provides the error handling sequence for restartable
 * system calls.
 */
#ifdef PIC
#define SYSRESTART(x) \
	bcc	noerr; \
	cmp	%o0, SV_ERESTART; \
	be,a	x; \
	ld	 [%sp+68], %o0; \
	PIC_SETUP(o5); \
	ld	[%o5 + .cerror], %o5; \
	jmp	%o5; \
	.empty; \
noerr:	nop	; 
#else
#define SYSRESTART(x) \
	bcc	noerr; \
	cmp	%o0, SV_ERESTART; \
	be,a	x; \
	ld	[%sp+68], %o0; \
	ba	.cerror; \
	.empty; \
noerr:	nop	;
#endif

#define RET	retl; nop;

#ifdef PIC
#define CERROR(free_reg) \
	bcc	noerr; \
	PIC_SETUP(free_reg); \
	.empty;	\
	ld	[%free_reg+ .cerror],%free_reg; \
	jmp	%free_reg; \
	.empty;	\
noerr:	nop;	
#else
#define CERROR(free_reg) \
	bcc 	noerr; \
	.empty; \
	sethi	%hi(.cerror), %free_reg;\
	or	%free_reg, %lo(.cerror), %free_reg;\
	jmp	%free_reg;\
	.empty;\
noerr: nop;
#endif
