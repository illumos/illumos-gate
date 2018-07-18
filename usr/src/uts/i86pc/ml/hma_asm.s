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

/*
 * Copyright 2018 Joyent, Inc.
 */


#include <sys/asm_linkage.h>

#if defined(__lint)

int
hma_vmx_vmxon(uintptr_t arg)
{
	return (0);
}

#else	/* __lint */
	ENTRY_NP(hma_vmx_vmxon)
	push	%rbp
	movq	%rsp, %rbp
	pushq	%rdi

	xorl	%eax, %eax
	vmxon	-0x8(%rbp)
	ja	1f	/* CF=0, ZF=0 (success) */
	incl	%eax
1:

	leave
	ret
	SET_SIZE(hma_vmx_vmxon)
#endif	/* __lint */
