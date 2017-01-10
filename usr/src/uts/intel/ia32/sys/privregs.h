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

#ifndef	_IA32_SYS_PRIVREGS_H
#define	_IA32_SYS_PRIVREGS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This file describes the cpu's privileged register set, and
 * how the machine state is saved on the stack when a trap occurs.
 */

#if !defined(__i386)
#error	"non-i386 code depends on i386 privileged header!"
#endif

#ifndef _ASM

/*
 * This is NOT the structure to use for general purpose debugging;
 * see /proc for that.  This is NOT the structure to use to decode
 * the ucontext or grovel about in a core file; see <sys/regset.h>.
 */

struct regs {
	/*
	 * Extra frame for mdb to follow through high level interrupts and
	 * system traps.  Set them to 0 to terminate stacktrace.
	 */
	greg_t  r_savfp;	/* a copy of %ebp */
	greg_t  r_savpc;	/* a copy of %eip */

	greg_t	r_gs;
	greg_t	r_fs;
	greg_t	r_es;
	greg_t	r_ds;
	greg_t	r_edi;
	greg_t	r_esi;
	greg_t	r_ebp;
	greg_t	r_esp;
	greg_t	r_ebx;
	greg_t	r_edx;
	greg_t	r_ecx;
	greg_t	r_eax;
	greg_t	r_trapno;
	greg_t	r_err;
	greg_t	r_eip;
	greg_t	r_cs;
	greg_t	r_efl;
	greg_t	r_uesp;
	greg_t	r_ss;
};

#define	r_r0	r_eax		/* r0 for portability */
#define	r_r1	r_edx		/* r1 for portability */
#define	r_fp	r_ebp		/* system frame pointer */
#define	r_sp	r_uesp		/* user stack pointer */
#define	r_pc	r_eip		/* user's instruction pointer */
#define	r_ps	r_efl		/* user's EFLAGS */

#define	GREG_NUM	8	/* Number of regs between %edi and %eax */

#ifdef _KERNEL
#define	lwptoregs(lwp)	((struct regs *)((lwp)->lwp_regs))
#endif /* _KERNEL */

#else	/* !_ASM */

#if defined(_MACHDEP)

#include <sys/machprivregs.h>

/*
 * Save current frame on the stack.  Uses %eax.
 */
#define	__FRAME_PUSH				\
	subl	$8, %esp;			\
	movl	REGOFF_EIP(%esp), %eax;		\
	movl	%eax, REGOFF_SAVPC(%esp);	\
	movl	%ebp, REGOFF_SAVFP(%esp);

/*
 * Save segment registers on the stack.
 */
#define	__SEGREGS_PUSH		\
	subl	$16, %esp;	\
	movw	%ds, 12(%esp);	\
	movw	%es, 8(%esp);	\
	movw	%fs, 4(%esp);	\
	movw	%gs, 0(%esp);

/*
 * Load segment register with kernel selectors.
 * %gs must be the last one to be set to make the
 * check in cmnint valid.
 */
#define	__SEGREGS_LOAD_KERNEL	\
	movw	$KDS_SEL, %cx;	\
	movw	%cx, %ds;	\
	movw	%cx, %es;	\
	movw	$KFS_SEL, %cx;	\
	movw	$KGS_SEL, %dx;	\
	movw	%cx, %fs;	\
	movw	%dx, %gs;

/*
 * Restore segment registers off the stack.
 *
 * NOTE THE ORDER IS VITAL!
 *
 * Also note the subtle interdependency with kern_gpfault()
 * that needs to disassemble these instructions to diagnose
 * what happened when things (like bad segment register
 * values) go horribly wrong.
 */
#define	__SEGREGS_POP		\
	movw	0(%esp), %gs;	\
	movw	4(%esp), %fs;	\
	movw	8(%esp), %es;	\
	movw	12(%esp), %ds;	\
	addl	$16, %esp;

/*
 * Macros for saving all registers necessary on interrupt entry,
 * and restoring them on exit.
 */
#define	INTR_PUSH			\
	cld;				\
	pusha;				\
	__SEGREGS_PUSH			\
	__FRAME_PUSH			\
	cmpw	$KGS_SEL, REGOFF_GS(%esp); \
	je	8f;			\
	movl	$0, REGOFF_SAVFP(%esp);	\
	__SEGREGS_LOAD_KERNEL		\
8:	CLEAN_CS

#define	__INTR_POP			\
	popa;				\
	addl	$8, %esp;	/* get TRAPNO and ERR off the stack */

#define	INTR_POP_USER			\
	addl	$8, %esp;	/* get extra frame off the stack */ \
	__SEGREGS_POP			\
	__INTR_POP

#define	INTR_POP_KERNEL					\
	addl	$24, %esp;	/* skip extra frame and segment registers */ \
	__INTR_POP
/*
 * Macros for saving all registers necessary on system call entry,
 * and restoring them on exit.
 */
#define	SYSCALL_PUSH			\
	cld;				\
	pusha;				\
	__SEGREGS_PUSH			\
	subl	$8, %esp;		\
	pushfl;				\
	popl	%ecx;			\
	orl	$PS_IE, %ecx;		\
	movl	%ecx, REGOFF_EFL(%esp);	\
	movl	$0, REGOFF_SAVPC(%esp);	\
	movl	$0, REGOFF_SAVFP(%esp);	\
	__SEGREGS_LOAD_KERNEL;		\

#define	SYSENTER_PUSH			\
	cld;				\
	pusha;				\
	__SEGREGS_PUSH			\
	subl	$8, %esp;		\
	movl	$0, REGOFF_SAVPC(%esp);	\
	movl	$0, REGOFF_SAVFP(%esp);	\
	__SEGREGS_LOAD_KERNEL

#define	SYSCALL_POP			\
	INTR_POP_USER

#endif	/* _MACHDEP */

/*
 * This is used to set eflags to known values at the head of an
 * interrupt gate handler, i.e. interrupts are -already- disabled.
 */
#define	INTGATE_INIT_KERNEL_FLAGS	\
	pushl	$F_OFF;			\
	popfl

#endif	/* !_ASM */

#include <sys/controlregs.h>

/* Control register layout for panic dump */

#define	CREGSZ		36
#define	CREG_GDT	0
#define	CREG_IDT	8
#define	CREG_LDT	16
#define	CREG_TASKR	18
#define	CREG_CR0	20
#define	CREG_CR2	24
#define	CREG_CR3	28
#define	CREG_CR4	32

#if !defined(_ASM) && defined(_INT64_TYPE)

typedef	uint64_t	creg64_t;

struct cregs {
	creg64_t	cr_gdt;
	creg64_t	cr_idt;
	uint16_t	cr_ldt;
	uint16_t	cr_task;
	uint32_t	cr_cr0;
	uint32_t	cr_cr2;
	uint32_t	cr_cr3;
	uint32_t	cr_cr4;
};

#if defined(_KERNEL)
extern void getcregs(struct cregs *);
#endif	/* _KERNEL */

#endif	/* !_ASM && _INT64_TYPE */

#ifdef __cplusplus
}
#endif

#endif	/* !_IA32_SYS_PRIVREGS_H */
