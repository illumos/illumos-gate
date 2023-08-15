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

	.file	"memcpy.s"

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(memmove,function)
	ANSI_PRAGMA_WEAK(memcpy,function)

#include "SYS.h"

	ENTRY(memcpy)
	movl	%edi,%edx	/ save register variables
	pushl	%esi
	movl	8(%esp),%edi	/ %edi = dest address
	movl	12(%esp),%esi	/ %esi = source address
	movl	16(%esp),%ecx	/ %ecx = length of string
	movl	%edi,%eax	/ return value from the call

	shrl	$2,%ecx		/ %ecx = number of words to move
	rep ; smovl		/ move the words

	movl	16(%esp),%ecx	/ %ecx = number of bytes to move
	andl	$0x3,%ecx	/ %ecx = number of bytes left to move
	rep ; smovb		/ move the bytes

	popl	%esi		/ restore register variables
	movl	%edx,%edi
	ret
	SET_SIZE(memcpy)


	ENTRY(memmove)
	pushl	%edi		/ save off %edi, %esi and move destination
	movl	4+12(%esp),%ecx	/ get number of bytes to move
	pushl	%esi
	testl	%ecx,%ecx	/ if (n == 0)
	je	.CleanupReturn	/    return(s);
	movl	8+ 4(%esp),%edi	/ destination buffer address
	movl	8+ 8(%esp),%esi	/ source buffer address
.Common:
	movl	$3,%eax		/ heavily used constant
	cmpl	%esi,%edi	/ if (source addr > dest addr)
	leal	-1(%esi,%ecx),%edx
	jbe	.CopyRight	/
	cmpl	%edx,%edi
	jbe	.CopyLeft
.CopyRight:
	cmpl	$8,%ecx		/    if (size < 8 bytes)
	jbe	.OneByteCopy	/        goto fast short copy loop
.FourByteCopy:
	movl	%ecx,%edx	/    save count
	movl	%esi,%ecx	/    get source buffer 4 byte aligned
	andl	%eax,%ecx
	jz	.SkipAlignRight
	subl	%ecx,%edx
	rep;	smovb		/    do the byte part of copy
.SkipAlignRight:
	movl	%edx,%ecx
	shrl	$2,%ecx
	rep;	smovl		/    do the long word part
	movl	%edx,%ecx	/    compute bytes left to move
	andl	%eax,%ecx	/    complete copy of remaining bytes
	jz	.CleanupReturn
.OneByteCopy:
	rep;	smovb		/    do the byte part of copy
.CleanupReturn:
	popl	%esi		/  }
	popl	%edi		/  restore registers
	movl	4(%esp),%eax	/  set up return value
.Return:
	ret			/  return(dba);

.CopyLeft:
	std				/ reverse direction bit (RtoL)
	cmpl	$12,%ecx		/ if (size < 12)
	ja	.BigCopyLeft		/ {
	movl	%edx,%esi		/     src = src + size - 1
	leal	-1(%ecx,%edi),%edi	/     dst = dst + size - 1
	rep;	smovb			/    do the byte copy
	cld				/    reset direction flag to LtoR
	popl	%esi			/  }
	popl	%edi			/  restore registers
	movl	4(%esp),%eax		/  set up return value
	ret				/  return(dba);
.BigCopyLeft:				/ } else {
	xchgl	%edx,%ecx
	movl	%ecx,%esi		/ align source w/byte copy
	leal	-1(%edx,%edi),%edi
	andl	%eax,%ecx
	jz	.SkipAlignLeft
	addl	$1, %ecx		/ we need to insure that future
	subl	%ecx,%edx		/ copy is done on aligned boundary
	rep;	smovb
.SkipAlignLeft:
	movl	%edx,%ecx
	subl	%eax,%esi
	shrl	$2,%ecx			/ do 4 byte copy RtoL
	subl	%eax,%edi
	rep;	smovl
	andl	%eax,%edx		/ do 1 byte copy whats left
	jz	.CleanupReturnLeft
	movl	%edx,%ecx
	addl	%eax,%esi		/ rep; smovl instruction will decrement
	addl	%eax,%edi		/ %edi, %esi by four after each copy
					/ adding 3 will restore pointers to byte
					/ before last double word copied
					/ which is where they are expected to
					/ be for the single byte copy code
	rep;	smovb
.CleanupReturnLeft:
	cld				/ reset direction flag to LtoR
	popl	%esi
	popl	%edi			/ restore registers
	movl	4(%esp),%eax		/ set up return value
	ret				/ return(dba);
	SET_SIZE(memmove)
