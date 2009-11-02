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

	ENTRY(memmove)
	movl	0+12(%esp),%ecx	/ get number of bytes to move
	pushl	%esi		/ save off %edi, %esi and move destination
	pushl	%edi
	movl	8+ 4(%esp),%edi	/ destination buffer address
	movl	8+ 8(%esp),%esi	/ source buffer address
	movl	%edi, %eax
	testl	%ecx,%ecx
	jz	.Return

	cmpl	%esi,%edi	/ if (source addr > dest addr)
	leal	-1(%esi,%ecx),%edx	/ %edx = src + size - 1
	jbe	.memcpy_post	/ jump if dst <= src
	cmpl	%edx,%edi
	jbe	.CopyLeft	/ jump if dst <= src + size - 1
	jmp	.memcpy_post

	ENTRY(memcpy)
	pushl	%esi
	pushl	%edi

	movl	8+4(%esp),%edi	/ %edi = dest address
	movl	%edi, %eax	/ save this
	movl	8+8(%esp),%esi	/ %esi = source address
	movl	8+12(%esp),%ecx/ %ecx = length of string
				/ %edx scratch register
				/ %eax scratch register
.memcpy_post:	
	nop			/ this really helps, don't know why
				/ note:	cld is perf death on P4
	cmpl	$63,%ecx
	ja	.move_sse	/ not worth doing sse for less

.movew:	
	movl	%ecx,%edx	/ save byte cnt
	shrl	$2,%ecx		/ %ecx = number of words to move
	rep ; smovl		/ move the words


	andl	$0x3,%edx	/ %edx = number of bytes left to move
	jz	.Return		/ %edx <= 3, so just unroll the loop

	movb	(%esi), %cl
	movb	%cl, (%edi)
	decl	%edx
	jz	.Return
	movb	1(%esi), %cl
	movb	%cl, 1(%edi)
	decl	%edx
	jz	.Return
	movb	2(%esi), %cl
	movb	%cl, 2(%edi)

.Return:
	popl	%edi		/ restore register variables
	popl	%esi		
	ret

.move_sse:
	/
	/ time to 16 byte align destination
	/
	andl	$15, %eax
	jnz	.sse_unaligned	/ jmp if dest is unaligned
.sse:				/ dest is aligned, check source
	movl	%ecx, %edx	/ get byte count
	shrl	$6, %edx	/ number of 64 byte blocks to move
	testl	$15, %esi
	jnz	.sse_da		/ go to slow loop if source is unaligned
	cmpl	$65535, %ecx
	ja	.sse_sa_nt_loop
	
	/
	/ use aligned load since we're lucky
	/
.sse_sa_loop:
	prefetcht0 568(%esi)	/ prefetch source & copy 64 byte at a time
	prefetcht0 568(%edi)	/ prefetch source & copy 64 byte at a time
	movaps	0(%esi), %xmm0
	movaps	%xmm0, 0(%edi)	 
	movaps	16(%esi), %xmm1
	movaps	%xmm1, 16(%edi)
	movaps	32(%esi), %xmm2
	movaps	%xmm2, 32(%edi)	 
	movaps	48(%esi), %xmm3
	movaps	%xmm3, 48(%edi)
	addl	$64, %esi
	addl	$64, %edi
	decl	%edx
	jnz	.sse_sa_loop
	
.sse_cleanup:
	andl	$63, %ecx	/ compute remaining bytes
	movl	8+4(%esp), %eax	/ setup return value
	jz	.Return
	jmp	.movew
	
	/
	/ use aligned load since we're lucky
	/
	.align 16
.sse_sa_nt_loop:
	prefetchnta 16384(%esi)	/ prefetch source & copy 64 byte at a time
	movaps	(%esi), %xmm0
	movntps	%xmm0, 0(%edi)	 
	movaps	16(%esi), %xmm1
	movntps	%xmm1, 16(%edi)
	movaps	32(%esi), %xmm2
	movntps	%xmm2, 32(%edi)	 
	movaps	48(%esi), %xmm3
	movntps	%xmm3, 48(%edi)
	addl	$64, %esi
	addl	$64, %edi
	decl	%edx
	jnz	.sse_sa_nt_loop
#if defined(_SSE2_INSN)
	mfence
#elif defined(_SSE_INSN)
	sfence
#else
#error "Must have either SSE or SSE2"
#endif
	jmp	.sse_cleanup

	/
	/ Make certain that destination buffer becomes aligned
	/
.sse_unaligned:
	neg	%eax		/ subtract from 16 and get destination
	andl	$15, %eax	/ aligned on a 16 byte boundary
	movl	%ecx, %edx	/ saved count
	subl	%eax, %ecx	/ subtract from byte count
	cmpl	$64, %ecx	/ after aligning, will we still have 64 bytes?
	cmovb	%edx, %ecx	/ if not, restore original byte count,
	cmovb	8+4(%esp), %eax	/ and restore return value,
	jb	.movew		/ and do a non-SSE move.
	xchg	%ecx, %eax	/ flip for copy
	rep ; smovb		/ move the bytes
	xchg	%ecx, %eax	/ flip back
	jmp	.sse
	
	.align 16
.sse_da:
	cmpl	$65535, %ecx
	jbe	.sse_da_loop

	/
	/ use unaligned load since source doesn't line up
	/
.sse_da_nt_loop:
	prefetchnta 16384(%esi)	/ prefetch source & copy 64 byte at a time
	movups	0(%esi), %xmm0
	movntps	%xmm0, 0(%edi)	 
	movups	16(%esi), %xmm1
	movntps	%xmm1, 16(%edi)
	movups	32(%esi), %xmm2
	movntps	%xmm2, 32(%edi)	 
	movups	48(%esi), %xmm3
	movntps	%xmm3, 48(%edi)
	addl	$64, %esi
	addl	$64, %edi
	decl	%edx
	jnz	.sse_da_nt_loop
#if defined(_SSE2_INSN)
	mfence
#elif defined(_SSE_INSN)
	sfence
#else
#error "Must have either SSE or SSE2"
#endif
	jmp	.sse_cleanup
	/
	/ use unaligned load since source doesn't line up
	/
	.align	16
.sse_da_loop:
	prefetcht0 568(%esi)	/ prefetch source & copy 64 byte at a time
	prefetcht0 568(%edi)
	movups	0(%esi), %xmm0
	movaps	%xmm0, 0(%edi)	 
	movups	16(%esi), %xmm1
	movaps	%xmm1, 16(%edi)
	movups	32(%esi), %xmm2
	movaps	%xmm2, 32(%edi)	 
	movups	48(%esi), %xmm3
	movaps	%xmm3, 48(%edi)
	addl	$64, %esi
	addl	$64, %edi
	decl	%edx
	jnz	.sse_da_loop
	jmp	.sse_cleanup
	
	SET_SIZE(memcpy)


/ .CopyLeft handles the memmove case where we must perform the copy backwards,
/ because of overlap between src and dst. This is not particularly optimized.

.CopyLeft:
	movl	$3,%eax			/ heavily used constant
	std				/ reverse direction bit (RtoL)
	cmpl	$12,%ecx		/ if (size < 12)
	ja	.BigCopyLeft		/ {
	movl	%edx,%esi		/     src = src + size - 1
	leal	-1(%ecx,%edi),%edi	/     dst = dst + size - 1
	rep;	smovb			/    do the byte copy
	cld				/    reset direction flag to LtoR
	popl	%edi			/  }
	popl	%esi			/  restore registers
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
	popl	%edi
	popl	%esi			/ restore registers
	movl	4(%esp),%eax		/ set up return value
	ret				/ return(dba);
	SET_SIZE(memmove)
