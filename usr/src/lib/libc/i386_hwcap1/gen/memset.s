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

	.file	"memset.s"

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(memset,function)

	ENTRY(memset)
	pushl	%edi		/ save register variable
	movl	8(%esp),%edi	/ %edi = string address
	movl	12(%esp),%eax	/ %al = byte to duplicate
	movl	16(%esp),%ecx	/ %ecx = number of copies

	/ For all basic blocks in this routine, maintain the following
	/ entry conditions:	%eax each byte is set to desired byte.
	/			NOTE: .byteset doesn't require this
	/			%ecx contains # bytes to set
	/			%edi contain address to set

	cld			/ make sure we go the right way...
	cmpl	$20,%ecx	/ strings with fewer than 20 chars should be byte set
	jbe	.byteset	

	andl	$0xff, %eax	/ trim anything above low byte
	imul	$0x01010101, %eax	/ extend low byte to each byte
	
	cmpl	$256, %ecx	/ smaller areas don't benefit from alignment
	jbe	.wordset

	cmpl	$511, %ecx	/ areas smaller than this should be wordset
	jbe	.check_wordset	

	/
	/ prep work for sse temporal and non-temporal
	/

	pushl	%ebx		/ more registers are needed
	pushl	%esi		/ for alignment work

	/
	/ align address to 64 byte boundaries.
	/

	movl	%ecx, %ebx	/ save byte count
	movl	%edi, %esi	/ esi is scratch register
	andl	$63, %esi	/ bytes to align to 64 byte align addr
	neg	%esi		/ compute count of bytes 
	addl	$64, %esi	/ needed to align
	andl	$63, %esi	/ to 64 byte align addr
	jz	.sse_aligned	/ skip alignment if not needed
	subl	%esi, %ebx	/ ebx contains remainder of bytes to set
	movl	%esi, %ecx	/ alignment bytes
	shrl	$2,%ecx		/ %ecx = number of words to set
	rep; sstol
	movl	%esi,%ecx
	andl	$3,%ecx		/ %ecx = number of bytes left
	rep; sstob
	movl	%ebx, %ecx	/ remainder to be set

.sse_aligned:
	
	shr	$6, %ecx	/ number of 64 byte blocks to set

	/
	/ load xmm0 with bytes to be set
	/
	subl	$16,%esp	/ give ourselves some working room on the stack
	movl	%eax,(%esp)	/ copy eax into each of 4 bytes
	movl	%eax,4(%esp)	/ avoid pushl since it causes more interlocking
	movl	%eax,8(%esp)	/
	movl	%eax,12(%esp)	/
	movups	(%esp), %xmm0	/ unaligned load from stack into xmm0
	addl	$16,%esp	/ restore stack position
	
	cmpl	$262143, %ebx	/ blocks smaller than this allocate in the cache
	jbe	.sse_loop
	jmp	.sse_nt_loop	/ branch across alignment nops
		
	.align 16

.sse_nt_loop:	
	movntps %xmm0, (%edi)	/ block non-temporal store
	movntps %xmm0, 16(%edi)	/ use sse rather than sse2
	movntps %xmm0, 32(%edi)	/ so we work more places
	movntps %xmm0, 48(%edi)	/

	addl	$64, %edi	/ increment dest address
	dec	%ecx		/ dec count of blocks
	jnz	.sse_nt_loop	/ jump if not done

	andl	$63, %ebx	/ remainder of bytes to copy
	movl	%ebx, %ecx	/ ecx contains remainer of bytes to set
	popl	%esi		/ restore stack config
	popl	%ebx		/
#if defined(_SSE2_INSN)
	mfence
#elif defined(_SSE_INSN)
	sfence
#else
#error "Must have either SSE or SSE2"
#endif
	cmpl	$20, %ecx	/ compare and jump accordingly
	jbe	.byteset
	jmp	.wordset	

	.align 16
.sse_loop:
 	movaps %xmm0, (%edi)	/ block copy w/ SSE
	movaps %xmm0, 16(%edi)
	movaps %xmm0, 32(%edi)
	movaps %xmm0, 48(%edi)

	addl	$64, %edi	/ increment addr
	dec	%ecx		/ dec count of blocks
	jnz	.sse_loop	/ jump if not done

	andl	$63, %ebx	/ remainder of bytes to copy
	movl	%ebx, %ecx	/ in %ecx as normal
	popl	%esi		/ restore stack config
	popl	%ebx		/
	cmpl	$20, %ecx	
	jbe	.byteset
	jmp	.wordset

.check_wordset:
	movl	%edi, %edx	/ save current store ptr
	andl	$7, %edi	/ check alignment
	movl	%edx,%edi	/ %edi = string address
	jz	.wordset	/ all ok 
	

.align_wordset:	
	pushl	%ebx		/ more registers are needed
	pushl	%esi		

	movl	%ecx, %ebx
	movl	%edi, %esi
	andl	$7, %esi
	neg	%esi
	addl	$8, %esi
	andl	$7, %esi
	subl	%esi, %ebx	/ ebx contains remainder of bytes to copy
	movl	%esi, %ecx
	rep; sstob	 
	movl	%ebx, %ecx
	popl	%esi		/ restore stack config
	popl	%ebx		/

.wordset:
	movl	%ecx, %edx	/ save cont
	shrl	$2,%ecx		/ %ecx = number of words to set
	rep; sstol
	movl	%edx,%ecx
	andl	$3,%ecx		/ %ecx = number of bytes left

.byteset:
	rep; sstob
	movl	8(%esp),%eax	/ return string address
	popl	%edi		/ restore register variable
	ret
	SET_SIZE(memset)
