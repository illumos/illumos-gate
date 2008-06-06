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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

	.file	"%M%"

#include "SYS.h"
#include <sys/trap.h>

	ANSI_PRAGMA_WEAK(syscall,function)

/*
 * See sparc/sys/syscall.s to understand why _syscall6() exists.
 * On x86, the implementation of the two are the same, the only
 * difference being that _syscall6 is not an exported symbol.
 */
	ENTRY2(syscall,_syscall6)
	popl	%edx		/ return address
	popl	%eax		/ system call number
	pushl	%edx
#if defined(_SYSC_INSN)
	.byte	0xf, 0x5	/* syscall */
#elif defined(_SEP_INSN)
	call	8f
8:	popl	%edx
	movl	%esp, %ecx
	addl	$[9f - 8b], %edx
	sysenter
9:
#else
	int	$T_SYSCALLINT
#endif
	movl	0(%esp), %edx
	pushl	%edx		/ restore the return address
	SYSCERROR
	ret
	SET_SIZE(syscall)
	SET_SIZE(_syscall6)

/*
 * See sparc/sys/syscall.s to understand why __systemcall6() exists.
 * On x86, the implementation of the two are the same, the only
 * difference being that __systemcall6 is not an exported symbol.
 *
 * WARNING WARNING WARNING:
 * The int $T_SYSCALL instruction below is needed by /proc when it scans a
 * controlled process's text for a syscall instruction.  It must be present in
 * all libc variants because /proc cannot use an optimized syscall instruction
 * to enter the kernel; optimized syscalls could be disabled by private LDT use.
 * We must leave at least one int $T_SYSCALLINT in the text for /proc to find
 * (see the Pscantext() routine).
 */
	ENTRY2(__systemcall,__systemcall6)
	popl	%edx		/ return address
	popl	%ecx		/ structure return address
	popl	%eax		/ system call number
	pushl	%edx
	int	$T_SYSCALLINT
	jae	1f
	/ error; clear syscall return values in the structure
	movl	$-1, 0(%ecx)	/ sys_rval1
	movl	$-1, 4(%ecx)	/ sys_rval2
	jmp	2f		/ %eax contains the error number
1:
	/ no error; copy syscall return values to the structure
	movl	%eax, 0(%ecx)	/ sys_rval1
	movl	%edx, 4(%ecx)	/ sys_rval2
	xorl	%eax, %eax	/ no error, set %eax to zero
2:
	movl	0(%esp), %edx	/ Restore the stack frame to original size
	pushl	%ecx
	pushl	%edx		/ restore the return address
	ret
	SET_SIZE(__systemcall)
	SET_SIZE(__systemcall6)
