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
 * Copyright 2019 Joyent, Inc.
 * Copyright 2024 MNX Cloud, Inc.
 */

	.file	"retpoline.s"

/*
 * This file implements the various hooks that are needed for retpolines and
 * return stack buffer (RSB) stuffing. For more information, please see the
 * 'Speculative Execution CPU Side Channel Security' section of the
 * uts/i86pc/os/cpuid.c big theory statement.
 */

#include <sys/asm_linkage.h>
#include <sys/x86_archext.h>

#if defined(__amd64)

/*
 * This macro generates the default retpoline entry point that the compiler
 * expects. It implements the expected retpoline form.
 */
#define	RETPOLINE_MKTHUNK(reg) \
	ENTRY(__x86_indirect_thunk_##reg)	\
	call	2f;				\
1:						\
	pause;					\
	lfence;					\
	jmp	1b;				\
2:						\
	movq	%##reg, (%rsp);		\
	ret;					\
	SET_SIZE(__x86_indirect_thunk_##reg)

/*
 * This macro generates the default retpoline form. It exists in addition to the
 * thunk so if we need to restore the default retpoline behavior to the thunk
 * we can.
 */
#define	RETPOLINE_MKGENERIC(reg) \
	ENTRY(__x86_indirect_thunk_gen_##reg)	\
	call	2f;				\
1:						\
	pause;					\
	lfence;					\
	jmp	1b;				\
2:						\
	movq	%##reg, (%rsp);		\
	ret;					\
	SET_SIZE(__x86_indirect_thunk_gen_##reg)

/*
 * This macro generates the no-op form of the retpoline which will be used if we
 * either need to disable retpolines because we have enhanced IBRS or because we
 * have been asked to disable mitigations.
 */
#define	RETPOLINE_MKJUMP(reg)			\
	ENTRY(__x86_indirect_thunk_jmp_##reg)	\
	jmp	*%##reg;			\
	SET_SIZE(__x86_indirect_thunk_jmp_##reg)

	RETPOLINE_MKTHUNK(rax)
	RETPOLINE_MKTHUNK(rbx)
	RETPOLINE_MKTHUNK(rcx)
	RETPOLINE_MKTHUNK(rdx)
	RETPOLINE_MKTHUNK(rdi)
	RETPOLINE_MKTHUNK(rsi)
	RETPOLINE_MKTHUNK(rbp)
	RETPOLINE_MKTHUNK(r8)
	RETPOLINE_MKTHUNK(r9)
	RETPOLINE_MKTHUNK(r10)
	RETPOLINE_MKTHUNK(r11)
	RETPOLINE_MKTHUNK(r12)
	RETPOLINE_MKTHUNK(r13)
	RETPOLINE_MKTHUNK(r14)
	RETPOLINE_MKTHUNK(r15)

	RETPOLINE_MKGENERIC(rax)
	RETPOLINE_MKGENERIC(rbx)
	RETPOLINE_MKGENERIC(rcx)
	RETPOLINE_MKGENERIC(rdx)
	RETPOLINE_MKGENERIC(rdi)
	RETPOLINE_MKGENERIC(rsi)
	RETPOLINE_MKGENERIC(rbp)
	RETPOLINE_MKGENERIC(r8)
	RETPOLINE_MKGENERIC(r9)
	RETPOLINE_MKGENERIC(r10)
	RETPOLINE_MKGENERIC(r11)
	RETPOLINE_MKGENERIC(r12)
	RETPOLINE_MKGENERIC(r13)
	RETPOLINE_MKGENERIC(r14)
	RETPOLINE_MKGENERIC(r15)

	RETPOLINE_MKJUMP(rax)
	RETPOLINE_MKJUMP(rbx)
	RETPOLINE_MKJUMP(rcx)
	RETPOLINE_MKJUMP(rdx)
	RETPOLINE_MKJUMP(rdi)
	RETPOLINE_MKJUMP(rsi)
	RETPOLINE_MKJUMP(rbp)
	RETPOLINE_MKJUMP(r8)
	RETPOLINE_MKJUMP(r9)
	RETPOLINE_MKJUMP(r10)
	RETPOLINE_MKJUMP(r11)
	RETPOLINE_MKJUMP(r12)
	RETPOLINE_MKJUMP(r13)
	RETPOLINE_MKJUMP(r14)
	RETPOLINE_MKJUMP(r15)

	/*
	 * The x86_rsb_stuff{,_vmexit} functions can be called from pretty
	 * arbitrary contexts. It's much easier for us to save and restore all
	 * the registers we touch rather than clobber them for callers. You
	 * must preserve this property or the system will panic at best.
	 *
	 * The reason for two entry points is because the need to RSB stuff
	 * on Intel depends greatly on factors that are different in the
	 * VMEXIT case, vs. the other context-switching cases
	 *
	 * See cpuid.c's cpuid_patch_rsb() for where the two entry points'
	 * NOPs actually get patched with one-byte RETs as need be, and the
	 * rules we use to determine which gets disabled with a RET, and which
	 * maintain their NOP to proceed to executing the stuffing sequence.
	 */
	ENTRY_NP(x86_rsb_stuff_vmexit)
	nop
	ALTENTRY(x86_rsb_stuff)
	nop
	pushq	%rdi
	pushq	%rax
	movl	$16, %edi
	movq	%rsp, %rax
rsb_loop:
	call	2f
1:
	pause
	call	1b
2:
	call	2f
1:
	pause
	call	1b
2:
	subl	$1, %edi
	jnz	rsb_loop
	movq	%rax, %rsp
	popq	%rax
	popq	%rdi
	ret
	SET_SIZE(x86_rsb_stuff)
	SET_SIZE(x86_rsb_stuff_vmexit)

#elif defined(__i386)

/*
 * While the kernel is 64-bit only, dboot is still 32-bit, so there are a
 * limited number of variants that are used for 32-bit. However as dboot is
 * short lived and uses them sparingly, we only do the full variant and do not
 * have an AMD specific version.
 */

#define	RETPOLINE_MKTHUNK(reg) \
	ENTRY(__x86_indirect_thunk_##reg)	\
	call	2f;				\
1:						\
	pause;					\
	lfence;					\
	jmp	1b;				\
2:						\
	movl	%##reg, (%esp);		\
	ret;					\
	SET_SIZE(__x86_indirect_thunk_##reg)

	RETPOLINE_MKTHUNK(edi)
	RETPOLINE_MKTHUNK(eax)

#else
#error	"Your architecture is in another castle."
#endif
