/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/asm_linkage.h>
#include <sys/segments.h>

/*
 * %rdi = trapno
 *
 * This variant is for any explicit exception injection that we need: in this
 * case, we can't just, for example, do a direct "int $2", as that will then
 * trash our %cr3 via tr_nmiint due to KPTI, so we have to fake a trap frame.
 * Both NMIs and MCEs don't push an 'err' into the frame.
 */
ENTRY_NP(vmm_call_trap)
	pushq	%rbp
	movq	%rsp, %rbp
	movq	%rsp, %r11
	andq	$~0xf, %rsp	/* align stack */
	pushq	$KDS_SEL	/* %ss */
	pushq	%r11		/* %rsp */
	pushfq			/* %rflags */
	pushq	$KCS_SEL	/* %cs */
	leaq	.trap_iret_dest(%rip), %rcx
	pushq	%rcx		/* %rip */
	cli
	cmpq	$T_NMIFLT, %rdi
	je	nmiint
	cmpq	$T_MCE, %rdi
	je	mcetrap

	pushq	%rdi		/* save our bad trapno... */
	leaq	__vmm_call_bad_trap(%rip), %rdi
	xorl	%eax, %eax
	call	panic
	/*NOTREACHED*/

.trap_iret_dest:
	popq	%rbp
	ret
SET_SIZE(vmm_call_trap)

__vmm_call_bad_trap:
	.string	"bad trapno for vmm_call_trap()"
