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
 * Copyright 2026 Oxide Computer Company
 */

#include <sys/asm_linkage.h>
#include "payload_common.h"

/* void outb(uint16_t port, uint8_t val) */
ENTRY(outb)
	movw    %di, %dx
	movb    %sil, %al
	outb    (%dx)
	ret
SET_SIZE(outb)

/* void outw(uint16_t port, uint16_t val) */
ENTRY(outw)
	movw    %di, %dx
	movw    %si, %ax
	outw    (%dx)
	ret
SET_SIZE(outb)

/* void outl(uint16_t port, uint32_t val) */
ENTRY(outl)
	movw    %di, %dx
	movl    %esi, %eax
	outl    (%dx)
	ret
SET_SIZE(outl)

/* uint8_t inb(uint16_t port) */
ENTRY(inb)
	movw    %di, %dx
	inb    (%dx)
	ret
SET_SIZE(inb)

/* uint16_t inw(uint16_t port) */
ENTRY(inw)
	movw    %di, %dx
	inw    (%dx)
	ret
SET_SIZE(inw)

/* uint32_t inl(uint16_t port) */
ENTRY(inl)
	movw    %di, %dx
	inl    (%dx)
	ret
SET_SIZE(inl)

/* uint64_t rdmsr(uint32_t msr) */
ENTRY(rdmsr)
	movl    %edi, %ecx
	rdmsr
	shlq    $32, %rdx
	orq     %rdx, %rax
	ret
SET_SIZE(rdmsr)

/* void wrmsr(uint32_t msr, uint64_t val) */
ENTRY(wrmsr)
	movq    %rsi, %rdx
	shrq    $32, %rdx
	movl    %esi, %eax
	movl    %edi, %ecx
	wrmsr
	ret
SET_SIZE(wrmsr)

/* void cpuid(uint32_t in_eax, uint32_t in_ecx, uint32_t *out_regs) */
ENTRY(cpuid)
	pushq   %rbx
	movl    %edi, %eax
	movl    %esi, %ecx
	movq    %rdx, %r8
	cpuid
	movl    %eax, (%r8)
	movl    %ebx, 4(%r8)
	movl    %ecx, 8(%r8)
	movl    %edx, 12(%r8)
	popq    %rbx
	ret
SET_SIZE(cpuid)

/* uint64_t rdtsc(void) */
ENTRY(rdtsc)
	rdtsc
	shlq    $32, %rdx
	orq     %rdx, %rax
	ret
SET_SIZE(rdtsc)

/* void ud2a(void) */
ENTRY(ud2a)
	ud2a
SET_SIZE(ud2a)

/* void setcr4(uint64_t) */
ENTRY(setcr4)
	movq    %rdi, %cr4
	ret
SET_SIZE(setcr4)

/* uint64_t getcr4(void) */
ENTRY(getcr4)
	movq    %cr4, %rax
	ret
SET_SIZE(getcr4)

/* void setxcr(uint32_t, uint64_t) */
ENTRY(setxcr)
	movq    %rsi, %rdx
	shrq    $32, %rdx
	movl    %esi, %eax
	movl    %edi, %ecx
	#xsetbv
	.byte   0x0f,0x01,0xd1
	ret
SET_SIZE(setxcr)

/* uint64_t getxcr(uint32_t) */
ENTRY(getxcr)
	movl	%edi, %ecx
	#xgetbv
	.byte 0x0f,0x01,0xd0
	shlq	$32, %rdx
	orq	%rdx, %rax
	ret
SET_SIZE(getxcr)

/* void test_result_pass(void) */
ENTRY(test_result_pass)
	movl    $IOP_TEST_RESULT, %edi
	movl    $TEST_RESULT_PASS, %esi
	call    outb
	ret
SET_SIZE(test_result_pass)

/* void test_result_fail(void) */
ENTRY(test_result_fail)
	movl    $IOP_TEST_RESULT, %edi
	movl    $TEST_RESULT_FAIL, %esi
	call    outb
	ret
SET_SIZE(test_result_fail)

/* void test_msg(const char *) */
ENTRY(test_msg)
	/*
	 * Message address is assumed to be in lower 32-bits, since that is where
	 * the payload is currently being mapped.
	 */
	movl    %edi, %esi
	movl    $IOP_TEST_MSG, %edi
	call    outl

	ret
SET_SIZE(test_msg)

/*
 * Rudimentary exception handling.
 *
 * The test harness loads the hidden segment state for %cs and %ss directly,
 * leaving the GDT empty, and points the IDTR at an empty table at MEM_LOC_IDT.
 * Without further setup, any exception raised by the payload escalates to a
 * triple fault (which some tests rely upon).  Payloads which wish to observe
 * exceptions call idt_init(), which:
 *
 * - Fills in GDT descriptors for the %cs and %ss selectors in use.
 * - Installs 64-bit interrupt handlers for the architectural exception vectors
 *   (0-31), pointing at the stubs below.
 *
 * An exception raised by an operation wrapped in one of the *_safe() accessors
 * resumes at that accessor's fixup address, which returns the vector to its
 * caller.  Any other exception is reported to the harness via IOP_TEST_EXC,
 * with its vector, error code and %rip.  For vectors marked resumable via
 * exc_set_resumable(), the payload then returns from the exception (so a fault
 * re-executes the faulting instruction), allowing the harness to inspect and
 * adjust guest state (registers, %cr2, page tables) before the payload goes
 * on.  Otherwise, the harness fails the test.
 */

/* Flat 64-bit code and data segment descriptors */
#define	GDT_DESC_CODE64	0x00af9b000000ffff
#define	GDT_DESC_DATA	0x00cf93000000ffff

/* Present, DPL 0, 64-bit interrupt gate, IST 0 */
#define	IDT_GATE_ATTR	0x8e00

#define	NUM_EXC_VECTORS	32

/*
 * Stubs for exceptions with and without an error code, so that exc_common
 * always finds a uniform frame of:
 *   - vector
 *   - error code
 *   - %rip
 *   - %cs
 *   - %rflags
 *   - %rsp
 *   - %ss
 */
#define	EXC_STUB(vec)		\
exc_stub_##vec:			\
	pushq	$0;		\
	pushq	$vec;		\
	jmp	exc_common

#define	EXC_STUB_ERR(vec)	\
exc_stub_##vec:			\
	pushq	$vec;		\
	jmp	exc_common

	.data
	.balign	8
/* %rip at which to resume when an exception is raised, if non-zero */
exc_fixup:
	.quad	0
/* Exception details reported to the harness: see `struct payload_exc_report` */
exc_report:
	.quad	0	/* per_errcode */
	.quad	0	/* per_rip */
	.byte	0	/* per_vector */
	.byte	0	/* per_resumable */
	.balign	8
/* Bitmap of vectors to resume from after reporting: see exc_set_resumable() */
exc_resume_mask:
	.long	0
/* Vector of the last exception taken through exc_fixup, or EXC_NONE */
exc_vector:
	.byte	EXC_NONE
	.balign	8

exc_stub_table:
	.quad	exc_stub_0, exc_stub_1, exc_stub_2, exc_stub_3
	.quad	exc_stub_4, exc_stub_5, exc_stub_6, exc_stub_7
	.quad	exc_stub_8, exc_stub_9, exc_stub_10, exc_stub_11
	.quad	exc_stub_12, exc_stub_13, exc_stub_14, exc_stub_15
	.quad	exc_stub_16, exc_stub_17, exc_stub_18, exc_stub_19
	.quad	exc_stub_20, exc_stub_21, exc_stub_22, exc_stub_23
	.quad	exc_stub_24, exc_stub_25, exc_stub_26, exc_stub_27
	.quad	exc_stub_28, exc_stub_29, exc_stub_30, exc_stub_31

	.text
	EXC_STUB(0)		/* #DE */
	EXC_STUB(1)		/* #DB */
	EXC_STUB(2)		/* NMI */
	EXC_STUB(3)		/* #BP */
	EXC_STUB(4)		/* #OF */
	EXC_STUB(5)		/* #BR */
	EXC_STUB(6)		/* #UD */
	EXC_STUB(7)		/* #NM */
	EXC_STUB_ERR(8)		/* #DF */
	EXC_STUB(9)		/* (reserved) */
	EXC_STUB_ERR(10)	/* #TS */
	EXC_STUB_ERR(11)	/* #NP */
	EXC_STUB_ERR(12)	/* #SS */
	EXC_STUB_ERR(13)	/* #GP */
	EXC_STUB_ERR(14)	/* #PF */
	EXC_STUB(15)		/* (reserved) */
	EXC_STUB(16)		/* #MF */
	EXC_STUB_ERR(17)	/* #AC */
	EXC_STUB(18)		/* #MC */
	EXC_STUB(19)		/* #XM */
	EXC_STUB(20)		/* #VE */
	EXC_STUB_ERR(21)	/* #CP */
	EXC_STUB(22)		/* (reserved) */
	EXC_STUB(23)		/* (reserved) */
	EXC_STUB(24)		/* (reserved) */
	EXC_STUB(25)		/* (reserved) */
	EXC_STUB(26)		/* (reserved) */
	EXC_STUB(27)		/* (reserved) */
	EXC_STUB(28)		/* #HV */
	EXC_STUB_ERR(29)	/* #VC */
	EXC_STUB_ERR(30)	/* #SX */
	EXC_STUB(31)		/* (reserved) */

/*
 * Common exception handling entry point jumped to by the EXC_STUBs.  They
 * ensure we end up here with a consistent stack layout:
 *
 *	 0(%rsp)	vector
 *	 8(%rsp)	error code (0 if the exception does not supply one)
 *	16(%rsp)	%rip
 *	24(%rsp)	%cs
 *	32(%rsp)	%rflags
 *	40(%rsp)	%rsp
 *	48(%rsp)	%ss
 *
 * All registers are preserved when resuming, either at a fixup or after a
 * report.  While handling the exception (up to and after inspection by the
 * harness), %rax, %rdx, %rsp, %rip, and %rflags may be modified.
 */
exc_common:
	pushq	%rax
	movq	exc_fixup(%rip), %rax
	testq	%rax, %rax
	jz	1f

	/* Want to resume at the fixup */
	movq	%rax, 24(%rsp)		/* saved rip = exc_fixup */
	movq	$0, exc_fixup(%rip)
	movq	8(%rsp), %rax
	movb	%al, exc_vector(%rip)
	popq	%rax
	addq	$16, %rsp
	iretq

1:
	/* No fixup armed: report the exception to the harness */
	pushq	%rdx
	movq	24(%rsp), %rax
	movq	%rax, exc_report(%rip)		/* per_errcode */
	movq	32(%rsp), %rax
	movq	%rax, exc_report+8(%rip)	/* per_rip */
	movq	16(%rsp), %rax
	movb	%al, exc_report+16(%rip)	/* per_vector */
	xorl	%edx, %edx
	btl	%eax, exc_resume_mask(%rip)
	setc	%dl
	movb	%dl, exc_report+17(%rip)	/* per_resumable */
	leaq	exc_report(%rip), %rax
	movw	$IOP_TEST_EXC, %dx
	outl	(%dx)

	/* Re-check if we should resume: the harness may have changed %rflags */
	cmpb	$0, exc_report+17(%rip)
	je	2f
	/* Return from the exception now that the harness has seen it */
	popq	%rdx
	popq	%rax
	addq	$16, %rsp
	iretq
2:
	/* The harness should fail the test, but do not return if it does not */
	hlt
	jmp	2b

/* void idt_init(void) */
ENTRY(idt_init)
	/* GDT descriptors for the %cs and %ss selectors in use */
	xorl	%eax, %eax
	movw	%cs, %ax
	andl	$~7, %eax
	movabsq	$GDT_DESC_CODE64, %rdx
	movq	%rdx, MEM_LOC_GDT(%rax)

	xorl	%eax, %eax
	movw	%ss, %ax
	andl	$~7, %eax
	movabsq	$GDT_DESC_DATA, %rdx
	movq	%rdx, MEM_LOC_GDT(%rax)

	/* Interrupt gates for the exception vectors */
	pushq	%rbx
	xorl	%ebx, %ebx
1:
	movl	%ebx, %edi
	leaq	exc_stub_table(%rip), %rax
	movq	(%rax, %rbx, 8), %rsi
	call	idt_set_gate
	incl	%ebx
	cmpl	$NUM_EXC_VECTORS, %ebx
	jb	1b
	popq	%rbx
	ret
SET_SIZE(idt_init)

/*
 * Point the IDT entry for vector %edi at the handler in %rsi via a 64-bit
 * interrupt gate.  Clobbers %rax, %rdx and %rdi.
 */
idt_set_gate:
	movl	%edi, %edi
	shlq	$4, %rdi
	addq	$MEM_LOC_IDT, %rdi
	movq	%rsi, %rax
	movw	%ax, 0(%rdi)		/* offset 15:0 */
	movw	%cs, %dx
	movw	%dx, 2(%rdi)		/* selector */
	movw	$IDT_GATE_ATTR, 4(%rdi)
	shrq	$16, %rax
	movw	%ax, 6(%rdi)		/* offset 31:16 */
	shrq	$16, %rax
	movl	%eax, 8(%rdi)		/* offset 63:32 */
	movl	$0, 12(%rdi)
	ret

/*
 * void exc_set_resumable(uint8_t vector)
 *
 * Exceptions on `vector` (which must be <NUM_EXC_VECTORS, otherwise raises #UD)
 * are reported to the harness and then returned from, rather than failing the
 * test.
 */
ENTRY(exc_set_resumable)
	movzbl	%dil, %edi
	cmpl	$NUM_EXC_VECTORS, %edi
	jae	1f
	btsl	%edi, exc_resume_mask(%rip)
	ret
1:
	ud2
SET_SIZE(exc_set_resumable)

/* uint8_t rdmsr_safe(uint32_t msr, uint64_t *valp) */
ENTRY(rdmsr_safe)
	leaq	1f(%rip), %rax
	movq	%rax, exc_fixup(%rip)
	movb	$EXC_NONE, exc_vector(%rip)
	movl	%edi, %ecx
	rdmsr
	shlq	$32, %rdx
	orq	%rdx, %rax
	movq	%rax, (%rsi)
1:
	movq	$0, exc_fixup(%rip)
	movzbl	exc_vector(%rip), %eax
	ret
SET_SIZE(rdmsr_safe)

/* uint8_t wrmsr_safe(uint32_t msr, uint64_t val) */
ENTRY(wrmsr_safe)
	leaq	1f(%rip), %rax
	movq	%rax, exc_fixup(%rip)
	movb	$EXC_NONE, exc_vector(%rip)
	movq	%rsi, %rdx
	shrq	$32, %rdx
	movl	%esi, %eax
	movl	%edi, %ecx
	wrmsr
1:
	movq	$0, exc_fixup(%rip)
	movzbl	exc_vector(%rip), %eax
	ret
SET_SIZE(wrmsr_safe)
