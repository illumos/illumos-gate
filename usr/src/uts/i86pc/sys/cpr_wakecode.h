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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_CPR_WC_H
#define	_CPR_WC_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	WC_CODESIZE	0x400

#if ! defined(_ASM)

#include <sys/rm_platter.h>
#include <sys/psm_types.h>

typedef	struct wc_cpu {
	uint64_t wc_retaddr;
	uint64_t wc_virtaddr;
	uint64_t wc_cr0;
	uint64_t wc_cr3;
	uint64_t wc_cr4;
	uint64_t wc_cr8;
	uint64_t wc_fs;
	uint64_t wc_fsbase;
	uint64_t wc_gs;
	uint64_t wc_gsbase;
	uint64_t wc_kgsbase;
	uint64_t wc_r8;
	uint64_t wc_r9;
	uint64_t wc_r10;
	uint64_t wc_r11;
	uint64_t wc_r12;
	uint64_t wc_r13;
	uint64_t wc_r14;
	uint64_t wc_r15;
	uint64_t wc_rax;
	uint64_t wc_rbp;
	uint64_t wc_rbx;
	uint64_t wc_rcx;
	uint64_t wc_rdi;
	uint64_t wc_rdx;
	uint64_t wc_rsi;
	uint64_t wc_rsp;

#if defined(__amd64)
	/*
	 * The compiler will want to 64-bit align the 64-bit rm_gdt_base
	 * pointer, so we need to add an extra four bytes of padding here to
	 * make sure rm_gdt_lim and rm_gdt_base will align to create a proper
	 * ten byte GDT pseudo-descriptor.
	 */
uint32_t wc_gdt_pad1;
#endif
	ushort_t wc_gdt_pad2;
	ushort_t wc_gdt_limit;
	user_desc_t *wc_gdt_base;

#if defined(__amd64)
	/*
	 * The compiler will want to 64-bit align the 64-bit rm_idt_base
	 * pointer, so we need to add an extra four bytes of padding here to
	 * make sure rm_idt_lim and rm_idt_base will align to create a proper
	 * ten byte IDT pseudo-descriptor.
	 */
uint32_t wc_idt_pad1;
#endif
	ushort_t wc_idt_pad2;
	ushort_t wc_idt_limit;
	user_desc_t *wc_idt_base;

#if defined(__amd64)
	uint64_t wc_tr;
	uint64_t wc_ldt;
	uint64_t wc_eflags;
#else
	uint32_t wc_tr;
	uint32_t wc_ldt;
	uint32_t wc_eflags;
#endif

	uint32_t wc_ebx;
	uint32_t wc_edi;
	uint32_t wc_esi;
	uint32_t wc_ebp;
	uint32_t wc_esp;
	uint16_t wc_ss;
	uint16_t wc_cs;
	uint16_t wc_ds;
	uint16_t wc_es;
	psm_state_request_t	wc_apic_state;
	processorid_t	wc_cpu_id;	/* which CPU are we running on */
	greg_t	*wc_saved_stack; /* pointer to where stack contents are saved */
	size_t	wc_saved_stack_size;	/* size of the saved stack */


	/* temp stack grows down to here */
} wc_cpu_t;

typedef struct wc_wakecode {
	rm_platter_t    wc_platter;
	wc_cpu_t	wc_cpu;

	/* temp stack grows down to here */
} wakecode_t;

/*
 * this is NOT correctly aligned, see description of idt & gdt, limit and
 * base in wc_cpu_t above
 */
typedef struct wc_desctbr {
	ushort_t	limit;
	void		*base;
} wc_desctbr_t;

extern int	wc_save_context(wc_cpu_t *);
extern void	wc_rm_start(void);
extern void	wc_rm_end(void);
extern void	(*cpr_start_cpu_func)(void);

#endif	/* ! defined(_ASM) */

#define	WC_STKSTART	0x7fc	/* end of rm_platter page */

#ifdef	__cplusplus
}
#endif

#endif	/* _CPR_WC_H */
