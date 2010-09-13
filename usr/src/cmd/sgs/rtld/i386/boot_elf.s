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
/*
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 *
 *	Copyright 2000-2002 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if	defined(lint)

#include	<sys/types.h>
#include	"_rtld.h"
#include	"_audit.h"
#include	"_elf.h"

/* ARGSUSED0 */
int
elf_plt_trace()
{
	return (0);
}
#else

#include	<link.h>
#include	"_audit.h"

	.file	"boot_elf.s"
	.text

/*
 * On entry the 'glue code' has already  done the following:
 *
 *	pushl	%ebp
 *	movl	%esp, %ebp
 *	pushl	dyndata_ptr
 *	jmp	elf_plt_trace
 *
 * so - -4(%ebp) contains the dyndata ptr
 *
 *	0x0	uintptr_t	reflmp
 *	0x4	uintptr_t	deflmp
 *	0x8	ulong_t		symndx
 *	0xc	ulont_t		sb_flags
 *	0x10	Elf32_Sym	symdef.st_name
 *	0x14			symdef.st_value
 *	0x18			symdef.st_size
 *	0x1c			symdef.st_info
 *	0x1d			symdef.st_other
 *	0x1e			symdef.st_shndx
 */
#define	REFLMP_OFF		0x0
#define	DEFLMP_OFF		0x4
#define	SYMNDX_OFF		0x8
#define	SBFLAGS_OFF		0xc
#define	SYMDEF_OFF		0x10
#define	SYMDEF_VALUE_OFF	0x14

	.globl	elf_plt_trace
	.type	elf_plt_trace,@function
	.align 16
elf_plt_trace:
	subl	$84,%esp			/ create some local storage
	pushl	%eax
	pushl	%ebx
	pushl	%edi
	pushl	%esi
	call	.L1				/ initialize %ebx to GOT
.L1:
	popl	%ebx
	addl	$_GLOBAL_OFFSET_TABLE_+[.-.L1], %ebx
	/*
	 * Local stack space storage is allocated as follows:
	 *
	 *	-4(%ebp)	store dyndata ptr
	 *	-8(%ebp)	store call destination
	 *	-84(%ebp)	space for gregset
	 *	-88(%ebp)	prev stack size
	 *	-92(%ebp)	entering %eax
	 *	-96(%ebp)	entering %ebx
	 *	-100(%ebp)	entering %edi
	 *	-104(%ebp)	entering %esi
	 */
	movl	-4(%ebp), %eax			/ %eax = dyndata
	testb	$LA_SYMB_NOPLTENTER, 0xc(%eax)	/ <link.h>
	je	.start_pltenter
	movl	SYMDEF_VALUE_OFF(%eax), %edi
	movl	%edi, -8(%ebp)			/ save destination address
	jmp	.end_pltenter

.start_pltenter:
	/*
	 * save all registers into gregset_t
	 */
	lea	4(%ebp), %edi
	movl	%edi, -84(%ebp)		/ %esp
	movl	0(%ebp), %edi
	movl	%edi, -80(%ebp)		/ %ebp
	/*
	 * trapno, err, eip, cs, efl, uesp, ss
	 */
	movl	-4(%ebp), %edi
	lea	SBFLAGS_OFF(%edi), %eax
	pushl	%eax				/ arg5 (&sb_flags)
	lea	-84(%ebp), %eax
	pushl	%eax				/ arg4 (regset)
	pushl	SYMNDX_OFF(%edi)		/ arg3 (symndx)
	lea	SYMDEF_OFF(%edi), %eax
	pushl	%eax				/ arg2 (&sym)
	pushl	DEFLMP_OFF(%edi)		/ arg1 (dlmp)
	pushl	REFLMP_OFF(%edi)		/ arg0 (rlmp)
	call	audit_pltenter@PLT
	addl	$24, %esp			/ cleanup stack
	movl	%eax, -8(%ebp)			/ save calling address
.end_pltenter:

	/*
	 * If *no* la_pltexit() routines exist
	 * we do not need to keep the stack frame
	 * before we call the actual routine.  Instead we
	 * jump to it and remove our stack from the stack
	 * at the same time.
	 */
	movl	audit_flags@GOT(%ebx), %eax
	movl	(%eax), %eax
	andl	$AF_PLTEXIT, %eax		/ value of audit.h:AF_PLTEXIT
	cmpl	$0, %eax
	je	.bypass_pltexit
	/*
	 * Has the *nopltexit* flag been set for this entry point
	 */
	testb	$LA_SYMB_NOPLTEXIT, 12(%edi)
	je	.start_pltexit

.bypass_pltexit:
	/*
	 * No PLTEXIT processing required.
	 */
	movl	0(%ebp), %eax
	movl	%eax, -4(%ebp)
	movl	-8(%ebp), %eax			/ eax == calling destination
	movl	%eax, 0(%ebp)			/ store destination at top

	popl	%esi				/
	popl	%edi				/    clean up stack
	popl	%ebx				/
	popl	%eax				/
	subl	$4, %ebp			/ adjust %ebp for 'ret'
	/*
	 * At this point, after a little doctoring, we should
	 * have the following on the stack:
	 *
	 *	8(%esp):  ret addr
	 *	4(%esp):  dest_addr
	 *	0(%esp):  Previous %ebp
	 *
	 * So - we pop the previous %ebp, and then
	 * ret to our final destination.
	 */
	movl	%ebp, %esp			/
	popl	%ebp				/
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
	movl	%ebp, %edi			/
	addl	$8, %edi			/    %edi = src
	movl	(%ebp), %edx			/
	subl	%edi, %edx			/    %edx == prev frame sz
	/*
	 * If audit_argcnt > 0 then we limit the number of
	 * arguements that will be duplicated to audit_argcnt.
	 *
	 * If (prev_stack_size > (audit_argcnt * 4))
	 *	prev_stack_size = audit_argcnt * 4;
	 */
	movl	audit_argcnt@GOT(%ebx),%eax
	movl	(%eax), %eax			/    %eax = audit_argcnt
	cmpl	$0, %eax
	jle	.grow_stack
	lea	(,%eax,4), %eax			/    %eax = %eax * 4
	cmpl	%eax,%edx
	jle	.grow_stack
	movl	%eax, %edx
	/*
	 * Grow the stack and duplicate the arguements of the
	 * original caller.
	 */
.grow_stack:
	subl	%edx, %esp			/    grow the stack 
	movl	%edx, -88(%ebp)			/    -88(%ebp) == prev frame sz
	movl	%esp, %ecx			/    %ecx = dest
	addl	%ecx, %edx			/    %edx == tail of dest
.while_base:
	cmpl	%edx, %ecx			/   while (base+size >= src++) {
	jge	.end_while				/
	movl	(%edi), %esi
	movl	%esi,(%ecx)			/        *dest = *src
	addl	$4, %edi			/	 src++
	addl	$4, %ecx			/        dest++
	jmp	.while_base			/    }

	/*
	 * The above stack is now an exact duplicate of
	 * the stack of the original calling procedure.
	 */
.end_while:
	movl	-92(%ebp), %eax			/ restore %eax
	movl	-96(%ebp), %ebx			/ restore %ebx
	movl	-104(%ebp), %esi		/ restore %esi

	movl	-8(%ebp), %edi
	call	*%edi				/ call dest_proc()

	addl	-88(%ebp), %esp			/ cleanup dupped stack

	movl	-4(%ebp), %edi
	pushl	SYMNDX_OFF(%edi)		/ arg4 (symndx)
	lea	SYMDEF_OFF(%edi), %ecx
	pushl	%ecx				/ arg3 (symp)
	pushl	DEFLMP_OFF(%edi)		/ arg2 (dlmp)
	pushl	REFLMP_OFF(%edi)		/ arg1 (rlmp)
	pushl	%eax				/ arg0 (retval)
	call	audit_pltexit@PLT
	addl	$20, %esp			/ cleanup stack
	
	/*
	 * Clean up after ourselves and return to the
	 * original calling procedure.
	 */
	popl	%esi				/
	popl	%edi				/ clean up stack
	popl	%ebx				/
	movl	%ebp, %esp			/
	popl	%ebp				/
	ret					/ return to caller
	.size	elf_plt_trace, .-elf_plt_trace
#endif

/*
 * We got here because a call to a function resolved to a procedure
 * linkage table entry.  That entry did a JMPL to the first PLT entry, which
 * in turn did a call to elf_rtbndr.
 *
 * the code sequence that got us here was:
 *
 * PLT entry for foo:
 *	jmp	*name1@GOT(%ebx)
 *	pushl	$rel.plt.foo
 *	jmp	PLT0
 *
 * 1st PLT entry (PLT0):
 *	pushl	4(%ebx)
 *	jmp	*8(%ebx)
 *	nop; nop; nop;nop;
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
	.globl	elf_bndr
	.globl	elf_rtbndr
	.weak	_elf_rtbndr
	_elf_rtbndr = elf_rtbndr	/ Make dbx happy
	.type   elf_rtbndr,@function
	.align	4

elf_rtbndr:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%eax
	pushl	%ecx
	pushl	%edx
	pushl	12(%ebp)		/ push pc
	pushl	8(%ebp)			/ push reloc
	pushl	4(%ebp)			/ push *lmp
	call	elf_bndr@PLT		/ call the C binder code
	addl	$12, %esp		/ pop args
	movl	%eax, 8(%ebp)		/ store final destination
	popl	%edx
	popl	%ecx
	popl	%eax
	movl	%ebp, %esp
	popl	%ebp
	addl	$4,%esp			/ pop args
	ret				/ invoke resolved function
	.size 	elf_rtbndr, .-elf_rtbndr
#endif
