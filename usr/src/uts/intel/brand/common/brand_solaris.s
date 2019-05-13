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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 */

/*
 * This is an assembly file that gets #include-ed into the brand-specific
 * assembly files (e.g. sn1_brand_asm.s) for Solaris-derived brands.
 * We can't make these into functions since in the trap context there's
 * no easy place to save the extra parameters that would be required, so
 * each brand module needs its own copy of this code.  We #include this and
 * use brand-specific #defines to replace the XXX_brand_... definitions.
 */ 

#ifdef lint

#include <sys/systm.h>

#else /* !lint */

#include <sys/asm_linkage.h>
#include <sys/privregs.h>
#include <sys/segments.h>
#include "assym.h"
#include "brand_asm.h"

#endif	/* !lint */

#ifdef  lint

void
XXX_brand_sysenter_callback(void)
{
}

void
XXX_brand_syscall_callback(void)
{
}

#if defined(__amd64)
void
XXX_brand_syscall32_callback(void)
{
}
#endif  /* amd64 */

void
XXX_brand_int91_callback(void)
{
}

#else   /* !lint */

#ifdef _ASM	/* The remainder of this file is only for assembly files */

#if defined(__amd64)

/*
 * syscall handler for 32-bit user processes:
 * See "64-BIT INTERPOSITION STACK" in brand_asm.h.
 * To 'return' to our user-space handler, we just need to place its address
 * into %rcx.  The original return address is passed back in SYSCALL_REG.
 */
ENTRY(XXX_brand_syscall32_callback)
	CALLBACK_PROLOGUE(XXX_emulation_table, SPD_HANDLER, SYSCALL_REG,
	    SCR_REG, SCR_REGB);
	CALC_TABLE_ADDR(SCR_REG, SPD_HANDLER);
	mov	%rcx, SYSCALL_REG; /* save orig return addr in syscall_reg */
	mov	SCR_REG, %rcx;	/* place new return addr in %rcx */
	mov	%gs:CPU_RTMP_R15, SCR_REG; /* restore scratch register */
	call	*x86_md_clear		/* Flush micro-arch state */
	mov	V_SSP(SP_REG), SP_REG	/* restore user stack pointer */
	jmp	nopop_sys_syscall32_swapgs_sysretl
9:
	retq
SET_SIZE(XXX_brand_syscall32_callback)

/*
 * syscall handler for 64-bit user processes:
 * See "64-BIT INTERPOSITION STACK" in brand_asm.h.
 * To 'return' to our user-space handler, we just need to place its address
 * into %rcx.  The original return address is passed back in SYSCALL_REG.
 */
ENTRY(XXX_brand_syscall_callback)
	CALLBACK_PROLOGUE(XXX_emulation_table, SPD_HANDLER, SYSCALL_REG,
	    SCR_REG, SCR_REGB);
	CALC_TABLE_ADDR(SCR_REG, SPD_HANDLER);
	mov	%rcx, SYSCALL_REG; /* save orig return addr in syscall_reg */
	mov	SCR_REG, %rcx;	/* place new return addr in %rcx */
	mov	%gs:CPU_RTMP_R15, SCR_REG; /* restore scratch register */
	call	*x86_md_clear		/* Flush micro-arch state */
	mov	V_SSP(SP_REG), SP_REG	/* restore user stack pointer */
	jmp	nopop_sys_syscall_swapgs_sysretq
9:
	retq
SET_SIZE(XXX_brand_syscall_callback)

/*
 * See "64-BIT INTERPOSITION STACK" in brand_asm.h.
 * To 'return' to our user-space handler, we just need to place its address
 * into %rdx.  The original return address is passed back in SYSCALL_REG.
 */
ENTRY(XXX_brand_sysenter_callback)
	CALLBACK_PROLOGUE(XXX_emulation_table, SPD_HANDLER, SYSCALL_REG,
	    SCR_REG, SCR_REGB);
	CALC_TABLE_ADDR(SCR_REG, SPD_HANDLER);
	mov	%rdx, SYSCALL_REG; /* save orig return addr in syscall_reg */
	mov	SCR_REG, %rdx;	/* place new return addr in %rdx */
	mov	%gs:CPU_RTMP_R15, SCR_REG; /* restore scratch register */
	mov	V_SSP(SP_REG), SP_REG	/* restore user stack pointer */
	jmp	sys_sysenter_swapgs_sysexit
9:
	ret
SET_SIZE(XXX_brand_sysenter_callback)

/*
 * To 'return' to our user-space handler we need to update the user's %eip
 * pointer in the saved interrupt state on the stack.  The interrupt state was
 * pushed onto our stack automatically when the interrupt occured; see the
 * comments above.  The original return address is passed back in SYSCALL_REG.
 * See "64-BIT INTERPOSITION STACK" and "64-BIT INT STACK" in brand_asm.h.
 */
ENTRY(XXX_brand_int91_callback)
	CALLBACK_PROLOGUE(XXX_emulation_table, SPD_HANDLER, SYSCALL_REG,
	    SCR_REG, SCR_REGB);
	CALC_TABLE_ADDR(SCR_REG, SPD_HANDLER); /* new ret addr is in scratch */
	mov	SCR_REG, SYSCALL_REG;	/* place new ret addr in syscallreg */
	mov	%gs:CPU_RTMP_R15, SCR_REG; /* restore scratch register */
	mov	V_SSP(SP_REG), SP_REG;	/* restore intr stack pointer */
	/*CSTYLED*/
	xchg	(SP_REG), SYSCALL_REG	/* swap new and orig. return addrs */
	jmp	sys_sysint_swapgs_iret
9:
	retq
SET_SIZE(XXX_brand_int91_callback)

#else	/* !__amd64 */

/*
 * To 'return' to our user-space handler, we need to replace the iret target
 * address.  The original return address is passed back in %eax.
 * See "32-BIT INTERPOSITION STACK" and "32-BIT INT STACK" in brand_asm.h.
 */
ENTRY(XXX_brand_syscall_callback)
	CALLBACK_PROLOGUE(XXX_emulation_table, SPD_HANDLER, SYSCALL_REG,
	    SCR_REG, SCR_REGB);
	CALC_TABLE_ADDR(SCR_REG, SPD_HANDLER); /* new ret addr is in scratch */
	mov	SCR_REG, SYSCALL_REG;	/* place new ret addr in syscallreg */
	GET_V(SP_REG, 0, V_U_EBX, SCR_REG); /* restore scratch register */
	add	$V_END, SP_REG;		/* restore intr stack pointer */
	/*CSTYLED*/
	xchg	(SP_REG), SYSCALL_REG	/* swap new and orig. return addrs */
	jmp	nopop_sys_rtt_syscall
9:
	ret
SET_SIZE(XXX_brand_syscall_callback)

/*
 * To 'return' to our user-space handler, we just need to place its address
 * into %edx.  The original return address is passed back in SYSCALL_REG.
 * See "32-BIT INTERPOSITION STACK" in brand_asm.h.
 */
ENTRY(XXX_brand_sysenter_callback)
	CALLBACK_PROLOGUE(XXX_emulation_table, SPD_HANDLER, SYSCALL_REG,
	    SCR_REG, SCR_REGB);
	mov	%edx, SCR_REG;	/* save orig return addr in scr reg */
	CALC_TABLE_ADDR(%edx, SPD_HANDLER); /* new return addr is in %edx */
	mov	SCR_REG, SYSCALL_REG;	/* save orig return addr in %eax */
	GET_V(SP_REG, 0, V_U_EBX, SCR_REG) /* restore scratch register */
	sysexit
9:
	ret
SET_SIZE(XXX_brand_sysenter_callback)

#endif	/* !__amd64 */
#endif	/* _ASM */
#endif  /* !lint */
