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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2018 Joyent, Inc. All rights reserved.
 */

/*
 * Welcome to the magic behind the PLT (procedure linkage table). When rtld
 * fills out the PLT entries, it will refer initially to the functions in this
 * file. As such our goal is simple:
 *
 *     The lie of the function call must be preserved at all costs.
 *
 * This means that we need to prepare the system for an arbitrary series of
 * instructions to be called. For example, as a side effect of resolving a
 * symbol we may need to open a shared object which will cause any _init
 * functions to be called. Those functions can use any and all of the ABI state
 * that they desire (for example, the FPU registers). Therefore we must save and
 * restore all the ABI mandated registers here.
 *
 * For the full information about what we need to save and restore and why,
 * please see the System V amd64 PS ABI '3.2.3 Parameter Passing'. For general
 * purpose registers, we need to take care of the following:
 *
 * 	%rax	- Used for information about the number of vector arguments
 *	%rdi	- arg0
 *	%rsi	- arg1
 *	%rdx	- arg2
 *	%rcx	- arg3
 *	%r8	- arg4
 *	%r9	- arg5
 *	%r10	- static chain pointer
 *
 * Unfortunately, the world of the FPU is more complicated.
 *
 * The ABI mandates that we must save %xmm0-%xmm7. On newer Intel processors,
 * %xmm0-%xmm7 shadow %ymm0-%ymm7 and %zmm0-%zmm7. Historically, when saving the
 * FPU, we only saved and restored these eight registers. Unfortunately, this
 * process itself ended up having side effects. Because the registers shadow one
 * another, if we saved a full %zmm register when only a %xmm register was
 * valid, we would end up causing the processor to think that the full %zmm
 * register was valid. Once it believed that this was the case, it would then
 * degrade performance of code that only used the %xmm registers.
 *
 * One way to tackle this problem would have been to use xgetbv with ecx=1 to
 * get information about what was actually in use and only save and restore
 * that. You can imagine that this logic roughly ends up as something like:
 *
 *         if (zmm_inuse)
 *		save_zmm()
 *         if (ymm_inuse)
 *		save_ymm()
 *         save_xmm()
 *
 * However, this logic leaves us at the mercy of the branch predictor. This
 * means that all of our efforts can end up still causing the CPU to execute
 * things to make it think that some of these other FPU registers are in use and
 * thus defeat the optimizations that it has.
 *
 * To deal with this problem, Intel has suggested using the xsave family of
 * instructions. The kernel provides information about the size required for the
 * floating point registers as well as which of several methods we need to
 * employ through the aux vector. This gets us out of trying to look at the
 * hardware capabilities and make decisions every time. As part of the
 * amd64-specific portion of rtld, it will process those values and determine
 * the functions on an as-needed basis.
 *
 * There are two different functions that we export. The first is elf_rtbndr().
 * This is basically the glue that gets us into the PLT and to perform
 * relocations. elf_rtbndr() determines the address of the function that we must
 * call and arranges its stack such that when we return from elf_rtbndr() we
 * will instead jump to the actual relocated function which will return to the
 * original caller. Because of this, we must preserve all of the registers that
 * are used for arguments and restore them before returning.
 *
 * The second function we export is elf_plt_trace(). This is used to add support
 * for audit libraries among other things. elf_plt_trace() may or may not call
 * the underlying function as a side effect or merely set up its return to it.
 * This changes how we handle %rax. If we call the function ourself, then we end
 * up making sure that %rax is the return value versus the initial value. In
 * addition, because we get %r11 from the surrounding PLT code, we opt to
 * preserve it in case some of the relocation logic ever ends up calling back
 * into us again.
 */

#if	defined(lint)

#include	<sys/types.h>
#include	<_rtld.h>
#include	<_audit.h>
#include	<_elf.h>
#include	<sys/regset.h>
#include	<sys/auxv_386.h>

#else

#include	<link.h>
#include	<_audit.h>
#include	<sys/asm_linkage.h>
#include	<sys/auxv_386.h>
#include	<sys/x86_archext.h>

/*
 * This macro is used to zero the xsave header. The contents of scratchreg will
 * be destroyed. locreg should contain the starting address of the xsave header.
 */
#define	XSAVE_HEADER_ZERO(scratch, loc) \
	xorq	scratch, scratch;	\
	movq	scratch, 0x200(loc);	\
	movq	scratch, 0x208(loc);	\
	movq	scratch, 0x210(loc);	\
	movq	scratch, 0x218(loc);	\
	movq	scratch, 0x220(loc);	\
	movq	scratch, 0x228(loc);	\
	movq	scratch, 0x230(loc);	\
	movq	scratch, 0x238(loc)


	.file	"boot_elf.s"
	.text

/*
 * This section of the code contains glue functions that are used to take care
 * of saving and restoring the FPU. We deal with this in a few different ways
 * based on the hardware support and what exists. Historically we've only saved
 * and restored the first 8 floating point registers rather than the entire FPU.
 * That implementation still exists here and is kept around mostly as an
 * insurance policy.
 */
	ENTRY(_elf_rtbndr_fp_save_orig)
	movq	org_scapset@GOTPCREL(%rip),%r11
	movq	(%r11),%r11		/* Syscapset_t pointer */
	movl	8(%r11),%edx		/* sc_hw_2 */
	testl	$AV_386_2_AVX512F,%edx
	jne	.save_zmm
	movl	(%r11),%edx		/* sc_hw_1 */
	testl	$AV_386_AVX,%edx
	jne	.save_ymm
	movdqa	%xmm0, (%rdi)
	movdqa	%xmm1, 64(%rdi)
	movdqa	%xmm2, 128(%rdi)
	movdqa	%xmm3, 192(%rdi)
	movdqa	%xmm4, 256(%rdi)
	movdqa	%xmm5, 320(%rdi)
	movdqa	%xmm6, 384(%rdi)
	movdqa	%xmm7, 448(%rdi)
	jmp	.save_finish

.save_ymm:
	vmovdqa	%ymm0, (%rdi)
	vmovdqa	%ymm1, 64(%rdi)
	vmovdqa	%ymm2, 128(%rdi)
	vmovdqa	%ymm3, 192(%rdi)
	vmovdqa	%ymm4, 256(%rdi)
	vmovdqa	%ymm5, 320(%rdi)
	vmovdqa	%ymm6, 384(%rdi)
	vmovdqa	%ymm7, 448(%rdi)
	jmp	.save_finish

.save_zmm:
	vmovdqa64	%zmm0, (%rdi)
	vmovdqa64	%zmm1, 64(%rdi)
	vmovdqa64	%zmm2, 128(%rdi)
	vmovdqa64	%zmm3, 192(%rdi)
	vmovdqa64	%zmm4, 256(%rdi)
	vmovdqa64	%zmm5, 320(%rdi)
	vmovdqa64	%zmm6, 384(%rdi)
	vmovdqa64	%zmm7, 448(%rdi)

.save_finish:
	ret
	SET_SIZE(_elf_rtbndr_fp_save_orig)

	ENTRY(_elf_rtbndr_fp_restore_orig)
	movq	org_scapset@GOTPCREL(%rip),%r11
	movq	(%r11),%r11		/* Syscapset_t pointer */
	movl	8(%r11),%edx		/* sc_hw_2 */
	testl	$AV_386_2_AVX512F,%edx
	jne	.restore_zmm
	movl	(%r11),%edx		/* sc_hw_1 */
	testl	$AV_386_AVX,%edx
	jne	.restore_ymm

	movdqa	(%rdi), %xmm0
	movdqa	64(%rdi), %xmm1
	movdqa	128(%rdi), %xmm2
	movdqa	192(%rdi), %xmm3
	movdqa	256(%rdi), %xmm4
	movdqa	320(%rdi), %xmm5
	movdqa	384(%rdi), %xmm6
	movdqa	448(%rdi), %xmm7
	jmp	.restore_finish

.restore_ymm:
	vmovdqa	(%rdi), %ymm0
	vmovdqa	64(%rdi), %ymm1
	vmovdqa	128(%rdi), %ymm2
	vmovdqa	192(%rdi), %ymm3
	vmovdqa	256(%rdi), %ymm4
	vmovdqa	320(%rdi), %ymm5
	vmovdqa	384(%rdi), %ymm6
	vmovdqa	448(%rdi), %ymm7
	jmp	.restore_finish

.restore_zmm:
	vmovdqa64	(%rdi), %zmm0
	vmovdqa64	64(%rdi), %zmm1
	vmovdqa64	128(%rdi), %zmm2
	vmovdqa64	192(%rdi), %zmm3
	vmovdqa64	256(%rdi), %zmm4
	vmovdqa64	320(%rdi), %zmm5
	vmovdqa64	384(%rdi), %zmm6
	vmovdqa64	448(%rdi), %zmm7

.restore_finish:
	ret
	SET_SIZE(_elf_rtbndr_fp_restore_orig)

	ENTRY(_elf_rtbndr_fp_fxsave)
	fxsaveq	(%rdi)
	ret
	SET_SIZE(_elf_rtbndr_fp_fxsave)

	ENTRY(_elf_rtbndr_fp_fxrestore)
	fxrstor	(%rdi)
	ret
	SET_SIZE(_elf_rtbndr_fp_fxrestore)

	ENTRY(_elf_rtbndr_fp_xsave)
	XSAVE_HEADER_ZERO(%rdx, %rdi)
	movq	$_CONST(XFEATURE_FP_ALL), %rdx
	movl	%edx, %eax
	shrq	$32, %rdx
	xsave	(%rdi)			/* save data */
	ret
	SET_SIZE(_elf_rtbndr_fp_xsave)

	ENTRY(_elf_rtbndr_fp_xrestore)
	movq	$_CONST(XFEATURE_FP_ALL), %rdx
	movl	%edx, %eax
	shrq	$32, %rdx
	xrstor	(%rdi)			/* save data */
	ret
	SET_SIZE(_elf_rtbndr_fp_xrestore)

#endif

#if	defined(lint)

/* ARGSUSED0 */
int
elf_plt_trace()
{
	return (0);
}

#else

/*
 * On entry the 'glue code' has already  done the following:
 *
 *	pushq	%rbp
 *	movq	%rsp, %rbp
 *	subq	$0x10, %rsp
 *	leaq	trace_fields(%rip), %r11
 *	movq	%r11, -0x8(%rbp)
 *	movq	$elf_plt_trace, %r11
 *	jmp	*%r11
 *
 * so - -8(%rbp) contains the dyndata ptr
 *
 *	0x0	Addr		*reflmp
 *	0x8	Addr		*deflmp
 *	0x10	Word		symndx
 *	0x14	Word		sb_flags
 *	0x18	Sym		symdef.st_name
 *	0x1c			symdef.st_info
 *	0x1d			symdef.st_other
 *	0x1e			symdef.st_shndx
 *	0x20			symdef.st_value
 *	0x28			symdef.st_size
 *
 * Also note - on entry 16 bytes have already been subtracted
 * from the %rsp.  The first 8 bytes is for the dyn_data_ptr,
 * the second 8 bytes are to align the stack and are available
 * for use.
 */
#define	REFLMP_OFF		0x0
#define	DEFLMP_OFF		0x8
#define	SYMNDX_OFF		0x10
#define	SBFLAGS_OFF		0x14
#define	SYMDEF_OFF		0x18
#define	SYMDEF_VALUE_OFF	0x20

/*
 * Next, we need to create a bunch of local storage. First, we have to preserve
 * the standard registers per the amd64 ABI. This means we need to deal with:
 *	%rax	- Used for information about the number of vector arguments
 *	%rdi	- arg0
 *	%rsi	- arg1
 *	%rdx	- arg2
 *	%rcx	- arg3
 *	%r8	- arg4
 *	%r9	- arg5
 *	%r10	- static chain pointer
 *	%r11	- PLT Interwork register, our caller is using this, so it's not
 *		  a temporary for us.
 *
 * In addition, we need to save the amd64 ABI floating point arguments. Finally,
 * we need to deal with our local storage. We need a La_amd64_regs and a
 * uint64_t for the previous stack size.
 *
 * To deal with this and the potentially variable size of the FPU regs, we have
 * to play a few different games. We refer to all of the standard registers, the
 * previous stack size, and La_amd64_regs structure off of %rbp. These are all
 * values that are below %rbp.
 */
#define	SPDYNOFF	-8
#define	SPDESTOFF	-16
#define	SPPRVSTKOFF	-24
#define	SPLAREGOFF	-88
#define	ORIG_RDI	-96
#define	ORIG_RSI	-104
#define	ORIG_RDX	-112
#define	ORIG_RCX	-120
#define	ORIG_R8		-128
#define	ORIG_R9		-136
#define	ORIG_R10	-144
#define	ORIG_R11	-152
#define	ORIG_RAX	-160
#define	PLT_SAVE_OFF	168

	ENTRY(elf_plt_trace)
	/*
	 * Save our static registers. After that 64-byte align us and subtract
	 * the appropriate amount for the FPU. The frame pointer has already
	 * been pushed for us by the glue code.
	 */
	movq	%rdi, ORIG_RDI(%rbp)
	movq	%rsi, ORIG_RSI(%rbp)
	movq	%rdx, ORIG_RDX(%rbp)
	movq	%rcx, ORIG_RCX(%rbp)
	movq	%r8, ORIG_R8(%rbp)
	movq	%r9, ORIG_R9(%rbp)
	movq	%r10, ORIG_R10(%rbp)
	movq	%r11, ORIG_R11(%rbp)
	movq	%rax, ORIG_RAX(%rbp)

	subq	$PLT_SAVE_OFF, %rsp

	movq	_plt_save_size@GOTPCREL(%rip),%r9
	movq	_plt_fp_save@GOTPCREL(%rip),%r10
	subq	(%r9), %rsp
	andq	$-64, %rsp
	movq	%rsp, %rdi
	call	*(%r10)

	/*
	 * Now that we've saved all of our registers, figure out what we need to
	 * do next.
	 */
	movq	SPDYNOFF(%rbp), %rax			/ %rax = dyndata
	testb	$LA_SYMB_NOPLTENTER, SBFLAGS_OFF(%rax)	/ <link.h>
	je	.start_pltenter
	movq	SYMDEF_VALUE_OFF(%rax), %rdi
	movq	%rdi, SPDESTOFF(%rbp)		/ save destination address
	jmp	.end_pltenter

.start_pltenter:
	/*
	 * save all registers into La_amd64_regs
	 */
	leaq	SPLAREGOFF(%rbp), %rsi	/ %rsi = &La_amd64_regs
	leaq	8(%rbp), %rdi
	movq	%rdi, 0(%rsi)		/ la_rsp
	movq	0(%rbp), %rdi
	movq	%rdi, 8(%rsi)		/ la_rbp
	movq	ORIG_RDI(%rbp), %rdi
	movq	%rdi, 16(%rsi)		/ la_rdi
	movq	ORIG_RSI(%rbp), %rdi
	movq	%rdi, 24(%rsi)		/ la_rsi
	movq	ORIG_RDX(%rbp), %rdi
	movq	%rdi, 32(%rsi)		/ la_rdx
	movq	ORIG_RCX(%rbp), %rdi
	movq	%rdi, 40(%rsi)		/ la_rcx
	movq	ORIG_R8(%rbp), %rdi
	movq	%rdi, 48(%rsi)		/ la_r8
	movq	ORIG_R9(%rbp), %rdi
	movq	%rdi, 56(%rsi)		/ la_r9

	/*
	 * prepare for call to la_pltenter
	 */
	movq	SPDYNOFF(%rbp), %r11		/ %r11 = &dyndata
	leaq	SBFLAGS_OFF(%r11), %r9		/ arg6 (&sb_flags)
	leaq	SPLAREGOFF(%rbp), %r8		/ arg5 (&La_amd64_regs)
	movl	SYMNDX_OFF(%r11), %ecx		/ arg4 (symndx)
	leaq	SYMDEF_OFF(%r11), %rdx		/ arg3 (&Sym)
	movq	DEFLMP_OFF(%r11), %rsi		/ arg2 (dlmp)
	movq	REFLMP_OFF(%r11), %rdi		/ arg1 (rlmp)
	call	audit_pltenter@PLT
	movq	%rax, SPDESTOFF(%rbp)		/ save calling address
.end_pltenter:

	/*
	 * If *no* la_pltexit() routines exist
	 * we do not need to keep the stack frame
	 * before we call the actual routine.  Instead we
	 * jump to it and remove our stack from the stack
	 * at the same time.
	 */
	movl	audit_flags(%rip), %eax
	andl	$AF_PLTEXIT, %eax		/ value of audit.h:AF_PLTEXIT
	cmpl	$0, %eax
	je	.bypass_pltexit
	/*
	 * Has the *nopltexit* flag been set for this entry point
	 */
	movq	SPDYNOFF(%rbp), %r11		/ %r11 = &dyndata
	testb	$LA_SYMB_NOPLTEXIT, SBFLAGS_OFF(%r11)
	je	.start_pltexit

.bypass_pltexit:
	/*
	 * No PLTEXIT processing required.
	 */
	movq	0(%rbp), %r11
	movq	%r11, -8(%rbp)			/ move prev %rbp
	movq	SPDESTOFF(%rbp), %r11		/ r11 == calling destination
	movq	%r11, 0(%rbp)			/ store destination at top

	/* Restore FPU */
	movq	_plt_fp_restore@GOTPCREL(%rip),%r10

	movq	%rsp, %rdi
	call	*(%r10)

	movq	ORIG_RDI(%rbp), %rdi
	movq	ORIG_RSI(%rbp), %rsi
	movq	ORIG_RDX(%rbp), %rdx
	movq	ORIG_RCX(%rbp), %rcx
	movq	ORIG_R8(%rbp), %r8
	movq	ORIG_R9(%rbp), %r9
	movq	ORIG_R10(%rbp), %r10
	movq	ORIG_R11(%rbp), %r11
	movq	ORIG_RAX(%rbp), %rax

	subq	$8, %rbp			/ adjust %rbp for 'ret'
	movq	%rbp, %rsp			/
	/*
	 * At this point, after a little doctoring, we should
	 * have the following on the stack:
	 *
	 *	16(%rsp):  ret addr
	 *	8(%rsp):  dest_addr
	 *	0(%rsp):  Previous %rbp
	 *
	 * So - we pop the previous %rbp, and then
	 * ret to our final destination.
	 */
	popq	%rbp				/
	ret					/ jmp to final destination
						/ and clean up stack :)

.start_pltexit:
	/*
	 * In order to call the destination procedure and then return
	 * to audit_pltexit() for post analysis we must first grow
	 * our stack frame and then duplicate the original callers
	 * stack state.  This duplicates all of the arguements
	 * that were to be passed to the destination procedure.
	 */
	movq	%rbp, %rdi			/
	addq	$16, %rdi			/    %rdi = src
	movq	(%rbp), %rdx			/
	subq	%rdi, %rdx			/    %rdx == prev frame sz
	/*
	 * If audit_argcnt > 0 then we limit the number of
	 * arguements that will be duplicated to audit_argcnt.
	 *
	 * If (prev_stack_size > (audit_argcnt * 8))
	 *	prev_stack_size = audit_argcnt * 8;
	 */
	movl	audit_argcnt(%rip),%eax		/   %eax = audit_argcnt
	cmpl	$0, %eax
	jle	.grow_stack
	leaq	(,%rax,8), %rax			/    %eax = %eax * 4
	cmpq	%rax,%rdx
	jle	.grow_stack
	movq	%rax, %rdx
	/*
	 * Grow the stack and duplicate the arguements of the
	 * original caller.
	 */
.grow_stack:
	movq	%rsp, %r11
	subq	%rdx, %rsp			/    grow the stack
	movq	%rdx, SPPRVSTKOFF(%rbp)		/    -88(%rbp) == prev frame sz
	movq	%rsp, %rcx			/    %rcx = dest
	addq	%rcx, %rdx			/    %rdx == tail of dest
.while_base:
	cmpq	%rdx, %rcx			/   while (base+size >= src++) {
	jge	.end_while			/
	movq	(%rdi), %rsi
	movq	%rsi,(%rcx)			/        *dest = *src
	addq	$8, %rdi			/	 src++
	addq	$8, %rcx			/        dest++
	jmp	.while_base			/    }

	/*
	 * The above stack is now an exact duplicate of
	 * the stack of the original calling procedure.
	 */
.end_while:
	/
	/ Restore registers using %r11 which contains our old %rsp value
	/ before growing the stack.
	/
	movq	_plt_fp_restore@GOTPCREL(%rip),%r10
	movq	%r11, %rdi
	call	*(%r10)

.trace_r2_finish:
	movq	ORIG_RDI(%rbp), %rdi
	movq	ORIG_RSI(%rbp), %rsi
	movq	ORIG_RDX(%rbp), %rdx
	movq	ORIG_RCX(%rbp), %rcx
	movq	ORIG_R8(%rbp), %r8
	movq	ORIG_R9(%rbp), %r9
	movq	ORIG_R10(%rbp), %r10
	movq	ORIG_RAX(%rbp), %rax
	movq	ORIG_R11(%rbp), %r11

	/*
	 * Call to desitnation function - we'll return here
	 * for pltexit monitoring.
	 */
	call	*SPDESTOFF(%rbp)

	addq	SPPRVSTKOFF(%rbp), %rsp	/ cleanup dupped stack

	/
	/ prepare for call to audit_pltenter()
	/
	movq	SPDYNOFF(%rbp), %r11		/ %r11 = &dyndata
	movq	SYMNDX_OFF(%r11), %r8		/ arg5 (symndx)
	leaq	SYMDEF_OFF(%r11), %rcx		/ arg4 (&Sym)
	movq	DEFLMP_OFF(%r11), %rdx		/ arg3 (dlmp)
	movq	REFLMP_OFF(%r11), %rsi		/ arg2 (rlmp)
	movq	%rax, %rdi			/ arg1 (returnval)
	call	audit_pltexit@PLT

	/*
	 * Clean up after ourselves and return to the
	 * original calling procedure. Make sure to restore
	 * registers.
	 */

	movq	_plt_fp_restore@GOTPCREL(%rip),%r10
	movq	%rsp, %rdi
	movq	%rax, SPPRVSTKOFF(%rbp)
	call	*(%r10)

	movq	ORIG_RDI(%rbp), %rdi
	movq	ORIG_RSI(%rbp), %rsi
	movq	ORIG_RDX(%rbp), %rdx
	movq	ORIG_RCX(%rbp), %rcx
	movq	ORIG_R8(%rbp), %r8
	movq	ORIG_R9(%rbp), %r9
	movq	ORIG_R10(%rbp), %r10
	movq	ORIG_R11(%rbp), %r11
	movq	SPPRVSTKOFF(%rbp), %rax

	movq	%rbp, %rsp			/
	popq	%rbp				/
	ret					/ return to caller
	SET_SIZE(elf_plt_trace)
#endif

/*
 * We got here because a call to a function resolved to a procedure
 * linkage table entry.  That entry did a JMPL to the first PLT entry, which
 * in turn did a call to elf_rtbndr.
 *
 * the code sequence that got us here was:
 *
 * .PLT0:
 *	pushq	GOT+8(%rip)	#GOT[1]
 *	jmp	*GOT+16(%rip)	#GOT[2]
 *	nop
 *	nop
 *	nop
 *	nop
 *	...
 * PLT entry for foo:
 *	jmp	*name1@GOTPCREL(%rip)
 *	pushl	$rel.plt.foo
 *	jmp	PLT0
 *
 * At entry, the stack looks like this:
 *
 *	return address			16(%rsp)
 *	$rel.plt.foo	(plt index)	8(%rsp)
 *	lmp				0(%rsp)
 *
 */
#if defined(lint)

extern unsigned long	elf_bndr(Rt_map *, unsigned long, caddr_t);

void
elf_rtbndr(Rt_map * lmp, unsigned long reloc, caddr_t pc)
{
	(void) elf_bndr(lmp, reloc, pc);
}

#else

/*
 * The PLT code that landed us here placed 2 arguments on the stack as
 * arguments to elf_rtbndr.
 * Additionally the pc of caller is below these 2 args.
 * Our stack will look like this after we establish a stack frame with
 * push %rbp; movq %rsp, %rbp sequence:
 *
 *	8(%rbp)			arg1 - *lmp
 *	16(%rbp), %rsi		arg2 - reloc index
 *	24(%rbp), %rdx		arg3 - pc of caller
 */
#define	LBPLMPOFF	8	/* arg1 - *lmp */
#define	LBPRELOCOFF	16	/* arg2 - reloc index */
#define	LBRPCOFF	24	/* arg3 - pc of caller */

/*
 * With the above in place, we must now proceed to preserve all temporary
 * registers that are also used for passing arguments. Specifically this
 * means:
 *
 *	%rax	- Used for information about the number of vector arguments
 *	%rdi	- arg0
 *	%rsi	- arg1
 *	%rdx	- arg2
 *	%rcx	- arg3
 *	%r8	- arg4
 *	%r9	- arg5
 *	%r10	- static chain pointer
 *
 * While we don't have to preserve %r11, we do have to preserve the FPU
 * registers. The FPU logic is delegated to a specific function that we'll call.
 * However, it requires that its stack is 64-byte aligned. We defer the
 * alignment to that point. This will also take care of the fact that a caller
 * may not call us with a correctly aligned stack pointer per the amd64 ABI.
 */

	.extern _plt_save_size
	.extern _plt_fp_save
	.extern plt_fp_restore

	.weak	_elf_rtbndr
	_elf_rtbndr = elf_rtbndr

	ENTRY(elf_rtbndr)
	pushq	%rbp		/* Establish stack frame */
	movq	%rsp, %rbp

	/*
	 * Save basic regs.
	 */
	pushq	%rax
	pushq	%rdi
	pushq	%rsi
	pushq	%rdx
	pushq	%rcx
	pushq	%r8
	pushq	%r9
	pushq	%r10
	pushq	%r12

	/*
	 * Save the amount of space we need for the FPU registers and call that
	 * function. Save %rsp before we manipulate it to make restore easier.
	 */
	movq	%rsp, %r12
	movq	_plt_save_size@GOTPCREL(%rip),%r9
	movq	_plt_fp_save@GOTPCREL(%rip),%r10
	subq	(%r9), %rsp
	andq	$-64, %rsp

	movq	%rsp, %rdi
	call	*(%r10)

	/*
	 * Perform actual PLT logic. Note that the plt related arguments are
	 * located at an offset relative to %rbp.
	 */
	movq	LBPLMPOFF(%rbp), %rdi	/* arg1 - *lmp */
	movq	LBPRELOCOFF(%rbp), %rsi	/* arg2 - reloc index */
	movq	LBRPCOFF(%rbp), %rdx	/* arg3 - pc of caller */
	call	elf_bndr@PLT		/* call elf_rtbndr(lmp, relndx, pc) */
	movq	%rax, LBPRELOCOFF(%rbp)	/* store final destination */

	/* Restore FPU */
	movq	_plt_fp_restore@GOTPCREL(%rip),%r10

	movq	%rsp, %rdi
	call	*(%r10)

	movq	%r12, %rsp
	popq	%r12
	popq	%r10
	popq	%r9
	popq	%r8
	popq	%rcx
	popq	%rdx
	popq	%rsi
	popq	%rdi
	popq	%rax

	movq	%rbp, %rsp	/* Restore our stack frame */
	popq	%rbp

	addq	$8, %rsp	/* pop 1st plt-pushed args */
				/* the second arguement is used */
				/* for the 'return' address to our */
				/* final destination */

	ret			/* invoke resolved function */

	SET_SIZE(elf_rtbndr)
#endif
