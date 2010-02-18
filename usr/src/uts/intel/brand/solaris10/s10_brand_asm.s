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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#if defined(lint)

#include <sys/systm.h>

#else	/* lint */

#include <s10_offsets.h>
#include "../common/brand_asm.h"

#endif	/* lint */

#ifdef	lint

void
s10_brand_sysenter_callback(void)
{
}

void
s10_brand_syscall_callback(void)
{
}

#if defined(__amd64)
void
s10_brand_syscall32_callback(void)
{
}
#endif	/* amd64 */

void
s10_brand_int91_callback(void)
{
}

#else	/* lint */

#if defined(__amd64)

/*
 * syscall handler for 32-bit user processes:
 *	%rcx - the address of the instruction after the syscall
 * See "64-BIT INTERPOSITION STACK" in brand_asm.h.
 */
ENTRY(s10_brand_syscall32_callback)
	SYSCALL_EMUL(s10_emulation_table, SPD_HANDLER, %rcx)
	jmp	nopop_sys_syscall32_swapgs_sysretl
9:
	retq
SET_SIZE(s10_brand_syscall32_callback)

/*
 * syscall handler for 64-bit user processes:
 *	%rcx - the address of the instruction after the syscall
 * See "64-BIT INTERPOSITION STACK" in brand_asm.h.
 */
ENTRY(s10_brand_syscall_callback)
	SYSCALL_EMUL(s10_emulation_table, SPD_HANDLER, %rcx)
	jmp	nopop_sys_syscall_swapgs_sysretq
9:
	retq
SET_SIZE(s10_brand_syscall_callback)

/*
 * %rdx - user space return address
 * See "64-BIT INTERPOSITION STACK" in brand_asm.h.
 */
ENTRY(s10_brand_sysenter_callback)
	SYSCALL_EMUL(s10_emulation_table, SPD_HANDLER, %rdx)
	jmp	sys_sysenter_swapgs_sysexit
9:
	ret
SET_SIZE(s10_brand_sysenter_callback)

/*
 * See "64-BIT INTERPOSITION STACK" and "64-BIT INT STACK" in brand_asm.h.
 */
ENTRY(s10_brand_int91_callback)
	INT_EMUL(s10_emulation_table, SPD_HANDLER)
	jmp	sys_sysint_swapgs_iret
9:
	retq
SET_SIZE(s10_brand_int91_callback)

#else	/* !__amd64 */

/*
 * See "32-BIT INTERPOSITION STACK" and "32-BIT INT STACK" in brand_asm.h.
 */
ENTRY(s10_brand_syscall_callback)
	INT_EMUL(s10_emulation_table, SPD_HANDLER)
	jmp	nopop_sys_rtt_syscall
9:
	ret
SET_SIZE(s10_brand_syscall_callback)

/*
 * %edx - user space return address
 * See "32-BIT INTERPOSITION STACK" in brand_asm.h.
 */
ENTRY(s10_brand_sysenter_callback)
	SYSCALL_EMUL(s10_emulation_table, SPD_HANDLER, %edx)
	sysexit
9:
	ret
SET_SIZE(s10_brand_sysenter_callback)

#endif	/* !__amd64 */
#endif	/* lint */
