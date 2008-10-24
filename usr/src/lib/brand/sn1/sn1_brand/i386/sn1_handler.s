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
 */

#include <sn1_misc.h>

#if defined(lint)

void
sn1_handler(void)
{
}

#else	/* lint */

#define	PIC_SETUP(r)					\
	call	9f;					\
9:							\
	popl	r;					\
	addl	$_GLOBAL_OFFSET_TABLE_ + [. - 9b], r

	/*
	 * %eax - syscall number
	 * stack contains:
	 *         --------------------------------------
	 *    |  8 | syscall arguments			|
	 *    v  4 | syscall wrapper return address	|
	 *  %esp+0 | syscall return address		|
	 *         --------------------------------------
	 */
	ENTRY_NP(sn1_handler)
	pushl	%ebp				/* allocate a stack frame */
	movl	%esp, %ebp

	/* Save registers at the time of the syscall. */
	movl	$0, EH_LOCALS_GREG(TRAPNO)(%ebp)
	movl	$0, EH_LOCALS_GREG(ERR)(%ebp)
	movl	%eax, EH_LOCALS_GREG(EAX)(%ebp)
	movl	%ebx, EH_LOCALS_GREG(EBX)(%ebp)
	movl	%ecx, EH_LOCALS_GREG(ECX)(%ebp)
	movl	%edx, EH_LOCALS_GREG(EDX)(%ebp)
	movl	%edi, EH_LOCALS_GREG(EDI)(%ebp)
	movl	%esi, EH_LOCALS_GREG(ESI)(%ebp)
	movl	%cs, EH_LOCALS_GREG(CS)(%ebp)
	movl	%ds, EH_LOCALS_GREG(DS)(%ebp)
	movl	%es, EH_LOCALS_GREG(ES)(%ebp)
	movl	%fs, EH_LOCALS_GREG(FS)(%ebp)
	movl	%gs, EH_LOCALS_GREG(GS)(%ebp)
	pushfl					/* save syscall flags */
	popl	%ecx
	movl	%ecx, EH_LOCALS_GREG(EFL)(%ebp)
	movl	EH_ARGS_OFFSET(0)(%ebp), %ecx	/* save syscall ebp */
	movl	%ecx, EH_LOCALS_GREG(EBP)(%ebp)
	movl	%ebp, %ecx			/* save syscall esp */
	addl	$CPTRSIZE, %ecx
	movl	%ecx, EH_LOCALS_GREG(ESP)(%ebp)
	movl	EH_ARGS_OFFSET(1)(%ebp), %ecx	/* save syscall ret address */
	movl	%ecx, EH_LOCALS_GREG(EIP)(%ebp)

	/*
	 * Finish setting up our stack frame.  We would normally do this
	 * upon entry to this function, but in this case we delayed it
	 * because a "sub" operation can modify flags and we wanted to
	 * save the flags into the gregset_t above before they get modified.
	 *
	 * Our stack frame format is documented in sn1_misc.h.
	 */
	subl	$EH_LOCALS_SIZE, %esp

	/* Look up the system call's entry in the sysent table */
	PIC_SETUP(%ecx)
	movl	sn1_sysent_table@GOT(%ecx), %edx   /* %edx = sysent_table */
	shll	$3, %eax	/* each entry is 8 bytes */
	add	%eax, %edx	/* %edx = sysent entry address */

	/*
	 * Get the return value flag and the number of arguments from the
	 * sysent table.
	 */
	movl	CPTRSIZE(%edx), %ecx		/* number of args + rv flag */
	andl	$RV_MASK, %ecx			/* strip out number of args */
	movl	%ecx, EH_LOCALS_RVFLAG(%ebp)	/* save rv flag */
	movl	CPTRSIZE(%edx), %ecx		/* number of args + rv flag */
	andl	$NARGS_MASK, %ecx		/* strip out rv flag */

	/*
	 * Setup arguments for our emulation call.  Our input arguments,
	 * 0 to N, will become emulation call arguments 1 to N+1.
	 * %ecx == number of arguments.
	 */
	movl	%ebp, %esi			/* args are at 12(%ebp) */
	addl	$EH_ARGS_OFFSET(3), %esi	
	movl	%esp, %edi			/* copy args to 4(%esp) */
	addl	$EH_ARGS_OFFSET(1), %edi	
	rep;	smovl				/* copy: (%esi) -> (%edi) */
						/* copy: %ecx 32-bit words */
	movl	EH_LOCALS_GREG(ESI)(%ebp), %esi	/* restore %esi */
	movl	EH_LOCALS_GREG(EDI)(%ebp), %edi	/* restore %edi */

	/*
	 * The first parameter to the emulation callback function is a
	 * pointer to a sysret_t structure.
	 */
	movl	%ebp, %ecx
	addl	$EH_LOCALS_SYSRET, %ecx
	movl	%ecx, EH_ARGS_OFFSET(0)(%esp)	/* arg0 == sysret_t ptr */

	/* invoke the emulation routine */
	ALTENTRY(sn1_handler_savepc)
	call	*(%edx)				/* call emulation routine */

	/* restore scratch registers */
	movl	EH_LOCALS_GREG(ECX)(%ebp), %ecx	/* restore %ecx */
	movl	EH_LOCALS_GREG(EDX)(%ebp), %edx	/* restore %edx */

	/* Check for syscall emulation success or failure */
	cmpl	$0, %eax			/* check for an error */
	je	success
	stc					/* failure, set carry flag */
	jmp	return				/* return, %rax == errno */

success:
	/* There is always at least one return value. */
	movl	EH_LOCALS_SYSRET1(%ebp), %eax	/* %eax == sys_rval1 */
	cmpl	$RV_DEFAULT, EH_LOCALS_RVFLAG(%ebp) /* check rv flag */
	je	clear_carry
	mov	EH_LOCALS_SYSRET2(%ebp), %edx	/* %edx == sys_rval2 */
clear_carry:
	clc					/* success, clear carry flag */

return:
	movl	%ebp, %esp			/* restore stack */
	popl	%ebp
	ret					/* ret to instr after syscall */
	SET_SIZE(sn1_handler)


#endif	/* lint */
