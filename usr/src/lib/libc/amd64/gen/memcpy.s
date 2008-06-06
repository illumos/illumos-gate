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

/*
 * Copyright (c) 2008, Intel Corporation
 * All rights reserved.
 */

/*
 * memcpy.s - copies two blocks of memory
 *	Implements memcpy() and memmove() libc primitives.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

	.file	"%M%"

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(memmove,function)
	ANSI_PRAGMA_WEAK(memcpy,function)

#include "cache.h"
#include "proc64_id.h"

#define L(s) .memcpy/**/s

/*
 * memcpy algorithm overview:
 *
 * Thresholds used below were determined experimentally.
 *
 * Pseudo code:
 *
 * If (size <= 128 bytes) {
 *	do unrolled code (primarily 8-byte loads/stores) regardless of
 *	alignment.
 * } else {
 *	Align destination to 16-byte boundary
 *
 *      if (NO_SSE) {
 *		If (size > half of the largest level cache) {
 *			Use 8-byte non-temporal stores (64-bytes/loop)
 *		} else {
 *			if (size > 4K && size <= half l1 cache size) {
 *				Use rep movsq
 *			} else {
 *				Use 8-byte loads/stores (64 bytes per loop)
 *			}
 *		}
 *
 *	} else { **USE SSE**
 *		If (size > half of the largest level cache) {
 *			Use 16-byte non-temporal stores (128-bytes per loop)
 *		} else {
 *			If (both source and destination are aligned) {
 *			    Use 16-byte aligned loads and stores (128 bytes/loop)
 *			} else {
 *			    use pairs of xmm registers with SSE2 or SSSE3
 *			    instructions to concatenate and shift appropriately
 *			    to account for source unalignment. This enables
 *			    16-byte aligned loads to be done.
 *			}
 *		}
	}
 *
 *	Finish any remaining bytes via unrolled code above.
 * }
 *
 * memmove overview:
 *	memmove is the same as memcpy except one case where copy needs to be
 *	done backwards. The copy backwards code is done in a similar manner.
 */

	ENTRY(memmove)
	cmp	%rsi,%rdi		# if dst <= src
	jbe	L(CopyForward)		# then do copy forward
	mov	%rsi,%r9		# move src to r9
	add	%rdx,%r9		# add len to get addr of end of src
	cmp	%r9,%rdi		# if dst < end of src
	jb	L(CopyBackwards)	# then do copy backwards
	jmp	L(CopyForward)

	ENTRY (memcpy)
L(CopyForward):
	mov    %rdx,%r8
	mov    %rdi,%rcx
	mov    %rsi,%rdx
	mov    %rdi,%rax
	lea    L(fwdPxQx)(%rip),%r11
	cmp    $0x80,%r8		# 128
	jg     L(ck_use_sse2)
	add    %r8,%rcx
	add    %r8,%rdx

	movslq (%r11,%r8,4),%r10
	lea    (%r10,%r11,1),%r11
	jmpq   *%r11

	.balign 16
L(ShrtAlignNew):
	lea    L(AliPxQx)(%rip),%r11  
	mov    %rcx,%r9
	and    $0xf,%r9

	movslq (%r11,%r9,4),%r10
	lea    (%r10,%r11,1),%r11
	jmpq   *%r11

	.balign 16
L(fwdPxQx): .int       L(P0Q0)-L(fwdPxQx)
           .int        L(P1Q0)-L(fwdPxQx)
           .int        L(P2Q0)-L(fwdPxQx)
           .int        L(P3Q0)-L(fwdPxQx)
           .int        L(P4Q0)-L(fwdPxQx)
           .int        L(P5Q0)-L(fwdPxQx)
           .int        L(P6Q0)-L(fwdPxQx)
           .int        L(P7Q0)-L(fwdPxQx) 

           .int        L(P0Q1)-L(fwdPxQx)
           .int        L(P1Q1)-L(fwdPxQx)
           .int        L(P2Q1)-L(fwdPxQx)
           .int        L(P3Q1)-L(fwdPxQx)
           .int        L(P4Q1)-L(fwdPxQx)
           .int        L(P5Q1)-L(fwdPxQx)
           .int        L(P6Q1)-L(fwdPxQx)
           .int        L(P7Q1)-L(fwdPxQx) 
 
           .int        L(P0Q2)-L(fwdPxQx)
           .int        L(P1Q2)-L(fwdPxQx)
           .int        L(P2Q2)-L(fwdPxQx)
           .int        L(P3Q2)-L(fwdPxQx)
           .int        L(P4Q2)-L(fwdPxQx)
           .int        L(P5Q2)-L(fwdPxQx)
           .int        L(P6Q2)-L(fwdPxQx)
           .int        L(P7Q2)-L(fwdPxQx) 

           .int        L(P0Q3)-L(fwdPxQx)
           .int        L(P1Q3)-L(fwdPxQx)
           .int        L(P2Q3)-L(fwdPxQx)
           .int        L(P3Q3)-L(fwdPxQx)
           .int        L(P4Q3)-L(fwdPxQx)
           .int        L(P5Q3)-L(fwdPxQx)
           .int        L(P6Q3)-L(fwdPxQx)
           .int        L(P7Q3)-L(fwdPxQx) 

           .int        L(P0Q4)-L(fwdPxQx)
           .int        L(P1Q4)-L(fwdPxQx)
           .int        L(P2Q4)-L(fwdPxQx)
           .int        L(P3Q4)-L(fwdPxQx)
           .int        L(P4Q4)-L(fwdPxQx)
           .int        L(P5Q4)-L(fwdPxQx)
           .int        L(P6Q4)-L(fwdPxQx)
           .int        L(P7Q4)-L(fwdPxQx) 

           .int        L(P0Q5)-L(fwdPxQx)
           .int        L(P1Q5)-L(fwdPxQx)
           .int        L(P2Q5)-L(fwdPxQx)
           .int        L(P3Q5)-L(fwdPxQx)
           .int        L(P4Q5)-L(fwdPxQx)
           .int        L(P5Q5)-L(fwdPxQx)
           .int        L(P6Q5)-L(fwdPxQx)
           .int        L(P7Q5)-L(fwdPxQx) 

           .int        L(P0Q6)-L(fwdPxQx)
           .int        L(P1Q6)-L(fwdPxQx)
           .int        L(P2Q6)-L(fwdPxQx)
           .int        L(P3Q6)-L(fwdPxQx)
           .int        L(P4Q6)-L(fwdPxQx)
           .int        L(P5Q6)-L(fwdPxQx)
           .int        L(P6Q6)-L(fwdPxQx)
           .int        L(P7Q6)-L(fwdPxQx) 

           .int        L(P0Q7)-L(fwdPxQx)
           .int        L(P1Q7)-L(fwdPxQx)
           .int        L(P2Q7)-L(fwdPxQx)
           .int        L(P3Q7)-L(fwdPxQx)
           .int        L(P4Q7)-L(fwdPxQx)
           .int        L(P5Q7)-L(fwdPxQx)
           .int        L(P6Q7)-L(fwdPxQx)
           .int        L(P7Q7)-L(fwdPxQx) 

           .int        L(P0Q8)-L(fwdPxQx)
           .int        L(P1Q8)-L(fwdPxQx)
           .int        L(P2Q8)-L(fwdPxQx)
           .int        L(P3Q8)-L(fwdPxQx)
           .int        L(P4Q8)-L(fwdPxQx)
           .int        L(P5Q8)-L(fwdPxQx)
           .int        L(P6Q8)-L(fwdPxQx)
           .int        L(P7Q8)-L(fwdPxQx) 

           .int        L(P0Q9)-L(fwdPxQx)
           .int        L(P1Q9)-L(fwdPxQx)
           .int        L(P2Q9)-L(fwdPxQx)
           .int        L(P3Q9)-L(fwdPxQx)
           .int        L(P4Q9)-L(fwdPxQx)
           .int        L(P5Q9)-L(fwdPxQx)
           .int        L(P6Q9)-L(fwdPxQx)
           .int        L(P7Q9)-L(fwdPxQx) 

           .int        L(P0QA)-L(fwdPxQx)
           .int        L(P1QA)-L(fwdPxQx)
           .int        L(P2QA)-L(fwdPxQx)
           .int        L(P3QA)-L(fwdPxQx)
           .int        L(P4QA)-L(fwdPxQx)
           .int        L(P5QA)-L(fwdPxQx)
           .int        L(P6QA)-L(fwdPxQx)
           .int        L(P7QA)-L(fwdPxQx) 

           .int        L(P0QB)-L(fwdPxQx)
           .int        L(P1QB)-L(fwdPxQx)
           .int        L(P2QB)-L(fwdPxQx)
           .int        L(P3QB)-L(fwdPxQx)
           .int        L(P4QB)-L(fwdPxQx)
           .int        L(P5QB)-L(fwdPxQx)
           .int        L(P6QB)-L(fwdPxQx)
           .int        L(P7QB)-L(fwdPxQx) 

           .int        L(P0QC)-L(fwdPxQx)
           .int        L(P1QC)-L(fwdPxQx)
           .int        L(P2QC)-L(fwdPxQx)
           .int        L(P3QC)-L(fwdPxQx)
           .int        L(P4QC)-L(fwdPxQx)
           .int        L(P5QC)-L(fwdPxQx)
           .int        L(P6QC)-L(fwdPxQx)
           .int        L(P7QC)-L(fwdPxQx) 

           .int        L(P0QD)-L(fwdPxQx)
           .int        L(P1QD)-L(fwdPxQx)
           .int        L(P2QD)-L(fwdPxQx)
           .int        L(P3QD)-L(fwdPxQx)
           .int        L(P4QD)-L(fwdPxQx)
           .int        L(P5QD)-L(fwdPxQx)
           .int        L(P6QD)-L(fwdPxQx)
           .int        L(P7QD)-L(fwdPxQx) 

           .int        L(P0QE)-L(fwdPxQx)
           .int        L(P1QE)-L(fwdPxQx)
           .int        L(P2QE)-L(fwdPxQx)
           .int        L(P3QE)-L(fwdPxQx)
           .int        L(P4QE)-L(fwdPxQx)
           .int        L(P5QE)-L(fwdPxQx)
           .int        L(P6QE)-L(fwdPxQx)
           .int        L(P7QE)-L(fwdPxQx) 

           .int        L(P0QF)-L(fwdPxQx)
           .int        L(P1QF)-L(fwdPxQx)
           .int        L(P2QF)-L(fwdPxQx)
           .int        L(P3QF)-L(fwdPxQx)
           .int        L(P4QF)-L(fwdPxQx)
           .int        L(P5QF)-L(fwdPxQx)
           .int        L(P6QF)-L(fwdPxQx)
           .int        L(P7QF)-L(fwdPxQx) 

           .int        L(P0QG)-L(fwdPxQx)	# 0x80

	   .balign 16
L(AliPxQx): .int   L(now_qw_aligned)-L(AliPxQx)
           .int        L(A1Q0)-L(AliPxQx)
           .int        L(A2Q0)-L(AliPxQx)
           .int        L(A3Q0)-L(AliPxQx)
           .int        L(A4Q0)-L(AliPxQx)
           .int        L(A5Q0)-L(AliPxQx)
           .int        L(A6Q0)-L(AliPxQx)
           .int        L(A7Q0)-L(AliPxQx)
           .int        L(A0Q1)-L(AliPxQx)
           .int        L(A1Q1)-L(AliPxQx)
           .int        L(A2Q1)-L(AliPxQx)
           .int        L(A3Q1)-L(AliPxQx)
           .int        L(A4Q1)-L(AliPxQx)
           .int        L(A5Q1)-L(AliPxQx)
           .int        L(A6Q1)-L(AliPxQx)
           .int        L(A7Q1)-L(AliPxQx)

	.balign 16
L(A1Q0):			# ; need to move 8+ 7=1+2+4 bytes
	movzbq (%rdx),%r11
	sub    $0xf,%r8
	mov    %r11b,(%rcx)

	movzwq 0x1(%rdx),%r10
	mov    %r10w,0x1(%rcx)

	mov    0x3(%rdx),%r9d
	mov    %r9d,0x3(%rcx)

	mov    0x7(%rdx),%r11
	add    $0xf,%rdx
	mov    %r11,0x7(%rcx)

	add    $0xf,%rcx
	jmp    L(now_qw_aligned)

	.balign 16
L(A2Q0):			# ; need to move 8+ 6=2+4 bytes
	movzwq (%rdx),%r10
	sub    $0xe,%r8
	mov    %r10w,(%rcx)

	mov    0x2(%rdx),%r9d
	mov    %r9d,0x2(%rcx)

	mov    0x6(%rdx),%r11
	add    $0xe,%rdx
	mov    %r11,0x6(%rcx)
	add    $0xe,%rcx
	jmp    L(now_qw_aligned)

	.balign 16
L(A3Q0):			# ; need to move 8+ 5=1+4 bytes
	movzbq (%rdx),%r11
	sub    $0xd,%r8
	mov    %r11b,(%rcx)

	mov    0x1(%rdx),%r9d
	mov    %r9d,0x1(%rcx)

	mov    0x5(%rdx),%r10
	add    $0xd,%rdx
	mov    %r10,0x5(%rcx)

	add    $0xd,%rcx
	jmp    L(now_qw_aligned)

	.balign 16
L(A4Q0):			# ; need to move 8+4 bytes
	mov    (%rdx),%r9d
	sub    $0xc,%r8
	mov    %r9d,(%rcx)

	mov    0x4(%rdx),%r10
	add    $0xc,%rdx
	mov    %r10,0x4(%rcx)

	add    $0xc,%rcx
	jmp    L(now_qw_aligned)

	.balign 16
L(A5Q0):			# ; need to move 8+ 3=1+2 bytes
	movzbq (%rdx),%r11
	sub    $0xb,%r8
	mov    %r11b,(%rcx)

	movzwq 0x1(%rdx),%r10
	mov    %r10w,0x1(%rcx)

	mov    0x3(%rdx),%r9
	add    $0xb,%rdx
	mov    %r9,0x3(%rcx)

	add    $0xb,%rcx
	jmp    L(now_qw_aligned)

	.balign 16
L(A6Q0):			# ; need to move 8+2 bytes
	movzwq (%rdx),%r10
	sub    $0xa,%r8
	mov    %r10w,(%rcx)

	mov    0x2(%rdx),%r9
	add    $0xa,%rdx
	mov    %r9,0x2(%rcx)

	add    $0xa,%rcx
	jmp    L(now_qw_aligned)

	.balign 16
L(A7Q0):			# ; need to move 8+1 byte
	movzbq (%rdx),%r11
	sub    $0x9,%r8
	mov    %r11b,(%rcx)

	mov    0x1(%rdx),%r10
	add    $0x9,%rdx
	mov    %r10,0x1(%rcx)

	add    $0x9,%rcx
	jmp    L(now_qw_aligned)

	.balign 16
L(A0Q1):			# ; need to move 8 bytes

	mov    (%rdx),%r10
	add    $0x8,%rdx
	sub    $0x8,%r8
	mov    %r10,(%rcx)

	add    $0x8,%rcx
	jmp    L(now_qw_aligned)

	.balign 16
L(A1Q1):			# ; need to move 7=1+2+4 bytes
	movzbq (%rdx),%r11
	sub    $0x7,%r8
	mov    %r11b,(%rcx)

	movzwq 0x1(%rdx),%r10
	mov    %r10w,0x1(%rcx)

	mov    0x3(%rdx),%r9d
	add    $0x7,%rdx
	mov    %r9d,0x3(%rcx)
	add    $0x7,%rcx
	jmp    L(now_qw_aligned)

	.balign 16
L(A2Q1):			# ; need to move 6=2+4 bytes
	movzwq (%rdx),%r10
	sub    $0x6,%r8
	mov    %r10w,(%rcx)
	mov    0x2(%rdx),%r9d
	add    $0x6,%rdx
	mov    %r9d,0x2(%rcx)
	add    $0x6,%rcx
	jmp    L(now_qw_aligned)

	.balign 16
L(A3Q1):			# ; need to move 5=1+4 bytes
	movzbq (%rdx),%r11
	sub    $0x5,%r8
	mov    %r11b,(%rcx)
	mov    0x1(%rdx),%r9d
	add    $0x5,%rdx
	mov    %r9d,0x1(%rcx)
	add    $0x5,%rcx
	jmp    L(now_qw_aligned)

	.balign 16
L(A4Q1):			# ; need to move 4 bytes
	mov    (%rdx),%r9d
	sub    $0x4,%r8
	add    $0x4,%rdx
	mov    %r9d,(%rcx)
	add    $0x4,%rcx
	jmp    L(now_qw_aligned)

	.balign 16
L(A5Q1):			# ; need to move 3=1+2 bytes
	movzbq (%rdx),%r11
	sub    $0x3,%r8
	mov    %r11b,(%rcx)

	movzwq 0x1(%rdx),%r10
	add    $0x3,%rdx
	mov    %r10w,0x1(%rcx)

	add    $0x3,%rcx
	jmp    L(now_qw_aligned)

	.balign 16
L(A6Q1):			# ; need to move 2 bytes
	movzwq (%rdx),%r10
	sub    $0x2,%r8
	add    $0x2,%rdx
	mov    %r10w,(%rcx)
	add    $0x2,%rcx
	jmp    L(now_qw_aligned)

	.balign 16
L(A7Q1):			# ; need to move 1 byte
	movzbq (%rdx),%r11
	dec    %r8
	inc    %rdx
	mov    %r11b,(%rcx)
	inc    %rcx
	jmp    L(now_qw_aligned)


	.balign 16              
L(P0QG):  
	mov    -0x80(%rdx),%r9
	mov    %r9,-0x80(%rcx)
L(P0QF):
	mov    -0x78(%rdx),%r10
	mov    %r10,-0x78(%rcx)
L(P0QE):
	mov    -0x70(%rdx),%r9
	mov    %r9,-0x70(%rcx)
L(P0QD):
	mov    -0x68(%rdx),%r10
	mov    %r10,-0x68(%rcx)
L(P0QC):
	mov    -0x60(%rdx),%r9
	mov    %r9,-0x60(%rcx)
L(P0QB):
	mov    -0x58(%rdx),%r10
	mov    %r10,-0x58(%rcx)
L(P0QA):
	mov    -0x50(%rdx),%r9
	mov    %r9,-0x50(%rcx)
L(P0Q9):
	mov    -0x48(%rdx),%r10
	mov    %r10,-0x48(%rcx)
L(P0Q8):
	mov    -0x40(%rdx),%r9
	mov    %r9,-0x40(%rcx)
L(P0Q7):
	mov    -0x38(%rdx),%r10
	mov    %r10,-0x38(%rcx)
L(P0Q6):
	mov    -0x30(%rdx),%r9
	mov    %r9,-0x30(%rcx)
L(P0Q5):
	mov    -0x28(%rdx),%r10
	mov    %r10,-0x28(%rcx)
L(P0Q4):
	mov    -0x20(%rdx),%r9
	mov    %r9,-0x20(%rcx)
L(P0Q3):
	mov    -0x18(%rdx),%r10
	mov    %r10,-0x18(%rcx)
L(P0Q2):
	mov    -0x10(%rdx),%r9
	mov    %r9,-0x10(%rcx)
L(P0Q1):
	mov    -0x8(%rdx),%r10
	mov    %r10,-0x8(%rcx)
L(P0Q0):                                   
	ret   

	.balign 16               
L(P1QF):
	mov    -0x79(%rdx),%r9
	mov    %r9,-0x79(%rcx)
L(P1QE):
	mov    -0x71(%rdx),%r11
	mov    %r11,-0x71(%rcx)
L(P1QD):
	mov    -0x69(%rdx),%r10
	mov    %r10,-0x69(%rcx)
L(P1QC):
	mov    -0x61(%rdx),%r9
	mov    %r9,-0x61(%rcx)
L(P1QB):
	mov    -0x59(%rdx),%r11
	mov    %r11,-0x59(%rcx)
L(P1QA):
	mov    -0x51(%rdx),%r10
	mov    %r10,-0x51(%rcx)
L(P1Q9):
	mov    -0x49(%rdx),%r9
	mov    %r9,-0x49(%rcx)
L(P1Q8):
	mov    -0x41(%rdx),%r11
	mov    %r11,-0x41(%rcx)
L(P1Q7):
	mov    -0x39(%rdx),%r10
	mov    %r10,-0x39(%rcx)
L(P1Q6):
	mov    -0x31(%rdx),%r9
	mov    %r9,-0x31(%rcx)
L(P1Q5):
	mov    -0x29(%rdx),%r11
	mov    %r11,-0x29(%rcx)
L(P1Q4):
	mov    -0x21(%rdx),%r10
	mov    %r10,-0x21(%rcx)
L(P1Q3):
	mov    -0x19(%rdx),%r9
	mov    %r9,-0x19(%rcx)
L(P1Q2):
	mov    -0x11(%rdx),%r11
	mov    %r11,-0x11(%rcx)
L(P1Q1):
	mov    -0x9(%rdx),%r10
	mov    %r10,-0x9(%rcx)
L(P1Q0):
	movzbq -0x1(%rdx),%r9
	mov    %r9b,-0x1(%rcx)
	ret   

	.balign 16               
L(P2QF):
	mov    -0x7a(%rdx),%r9
	mov    %r9,-0x7a(%rcx)
L(P2QE):
	mov    -0x72(%rdx),%r11
	mov    %r11,-0x72(%rcx)
L(P2QD):
	mov    -0x6a(%rdx),%r10
	mov    %r10,-0x6a(%rcx)
L(P2QC):
	mov    -0x62(%rdx),%r9
	mov    %r9,-0x62(%rcx)
L(P2QB):
	mov    -0x5a(%rdx),%r11
	mov    %r11,-0x5a(%rcx)
L(P2QA):
	mov    -0x52(%rdx),%r10
	mov    %r10,-0x52(%rcx)
L(P2Q9):
	mov    -0x4a(%rdx),%r9
	mov    %r9,-0x4a(%rcx)
L(P2Q8):
	mov    -0x42(%rdx),%r11
	mov    %r11,-0x42(%rcx)
L(P2Q7):
	mov    -0x3a(%rdx),%r10
	mov    %r10,-0x3a(%rcx)
L(P2Q6):
	mov    -0x32(%rdx),%r9
	mov    %r9,-0x32(%rcx)
L(P2Q5):
	mov    -0x2a(%rdx),%r11
	mov    %r11,-0x2a(%rcx)
L(P2Q4):
	mov    -0x22(%rdx),%r10
	mov    %r10,-0x22(%rcx)
L(P2Q3):
	mov    -0x1a(%rdx),%r9
	mov    %r9,-0x1a(%rcx)
L(P2Q2):
	mov    -0x12(%rdx),%r11
	mov    %r11,-0x12(%rcx)
L(P2Q1):
	mov    -0xa(%rdx),%r10
	mov    %r10,-0xa(%rcx)
L(P2Q0):
	movzwq -0x2(%rdx),%r9
	mov    %r9w,-0x2(%rcx)
	ret   

	.balign 16               
L(P3QF):
	mov    -0x7b(%rdx),%r9
	mov    %r9,-0x7b(%rcx)
L(P3QE):
	mov    -0x73(%rdx),%r11
	mov    %r11,-0x73(%rcx)
L(P3QD):
	mov    -0x6b(%rdx),%r10
	mov    %r10,-0x6b(%rcx)
L(P3QC):
	mov    -0x63(%rdx),%r9
	mov    %r9,-0x63(%rcx)
L(P3QB):
	mov    -0x5b(%rdx),%r11
	mov    %r11,-0x5b(%rcx)
L(P3QA):
	mov    -0x53(%rdx),%r10
	mov    %r10,-0x53(%rcx)
L(P3Q9):
	mov    -0x4b(%rdx),%r9
	mov    %r9,-0x4b(%rcx)
L(P3Q8):
	mov    -0x43(%rdx),%r11
	mov    %r11,-0x43(%rcx)
L(P3Q7):
	mov    -0x3b(%rdx),%r10
	mov    %r10,-0x3b(%rcx)
L(P3Q6):
	mov    -0x33(%rdx),%r9
	mov    %r9,-0x33(%rcx)
L(P3Q5):
	mov    -0x2b(%rdx),%r11
	mov    %r11,-0x2b(%rcx)
L(P3Q4):
	mov    -0x23(%rdx),%r10
	mov    %r10,-0x23(%rcx)
L(P3Q3):
	mov    -0x1b(%rdx),%r9
	mov    %r9,-0x1b(%rcx)
L(P3Q2):
	mov    -0x13(%rdx),%r11
	mov    %r11,-0x13(%rcx)
L(P3Q1):
	mov    -0xb(%rdx),%r10
	mov    %r10,-0xb(%rcx)
	/*
	 * These trailing loads/stores have to do all their loads 1st,
	 * then do the stores.
	 */
L(P3Q0):
	movzwq -0x3(%rdx),%r9
	movzbq -0x1(%rdx),%r10
	mov    %r9w,-0x3(%rcx)
	mov    %r10b,-0x1(%rcx)
	ret   

	.balign 16               
L(P4QF):
	mov    -0x7c(%rdx),%r9
	mov    %r9,-0x7c(%rcx)
L(P4QE):
	mov    -0x74(%rdx),%r11
	mov    %r11,-0x74(%rcx)
L(P4QD):
	mov    -0x6c(%rdx),%r10
	mov    %r10,-0x6c(%rcx)
L(P4QC):
	mov    -0x64(%rdx),%r9
	mov    %r9,-0x64(%rcx)
L(P4QB):
	mov    -0x5c(%rdx),%r11
	mov    %r11,-0x5c(%rcx)
L(P4QA):
	mov    -0x54(%rdx),%r10
	mov    %r10,-0x54(%rcx)
L(P4Q9):
	mov    -0x4c(%rdx),%r9
	mov    %r9,-0x4c(%rcx)
L(P4Q8):
	mov    -0x44(%rdx),%r11
	mov    %r11,-0x44(%rcx)
L(P4Q7):
	mov    -0x3c(%rdx),%r10
	mov    %r10,-0x3c(%rcx)
L(P4Q6):
	mov    -0x34(%rdx),%r9
	mov    %r9,-0x34(%rcx)
L(P4Q5):
	mov    -0x2c(%rdx),%r11
	mov    %r11,-0x2c(%rcx)
L(P4Q4):
	mov    -0x24(%rdx),%r10
	mov    %r10,-0x24(%rcx)
L(P4Q3):
	mov    -0x1c(%rdx),%r9
	mov    %r9,-0x1c(%rcx)
L(P4Q2):
	mov    -0x14(%rdx),%r11
	mov    %r11,-0x14(%rcx)
L(P4Q1):
	mov    -0xc(%rdx),%r10
	mov    %r10,-0xc(%rcx)
L(P4Q0):
	mov    -0x4(%rdx),%r9d
	mov    %r9d,-0x4(%rcx)
	ret   

	.balign 16               
L(P5QF):
	mov    -0x7d(%rdx),%r9
	mov    %r9,-0x7d(%rcx)
L(P5QE):
	mov    -0x75(%rdx),%r11
	mov    %r11,-0x75(%rcx)
L(P5QD):
	mov    -0x6d(%rdx),%r10
	mov    %r10,-0x6d(%rcx)
L(P5QC):
	mov    -0x65(%rdx),%r9
	mov    %r9,-0x65(%rcx)
L(P5QB):
	mov    -0x5d(%rdx),%r11
	mov    %r11,-0x5d(%rcx)
L(P5QA):
	mov    -0x55(%rdx),%r10
	mov    %r10,-0x55(%rcx)
L(P5Q9):
	mov    -0x4d(%rdx),%r9
	mov    %r9,-0x4d(%rcx)
L(P5Q8):
	mov    -0x45(%rdx),%r11
	mov    %r11,-0x45(%rcx)
L(P5Q7):
	mov    -0x3d(%rdx),%r10
	mov    %r10,-0x3d(%rcx)
L(P5Q6):
	mov    -0x35(%rdx),%r9
	mov    %r9,-0x35(%rcx)
L(P5Q5):
	mov    -0x2d(%rdx),%r11
	mov    %r11,-0x2d(%rcx)
L(P5Q4):
	mov    -0x25(%rdx),%r10
	mov    %r10,-0x25(%rcx)
L(P5Q3):
	mov    -0x1d(%rdx),%r9
	mov    %r9,-0x1d(%rcx)
L(P5Q2):
	mov    -0x15(%rdx),%r11
	mov    %r11,-0x15(%rcx)
L(P5Q1):
	mov    -0xd(%rdx),%r10
	mov    %r10,-0xd(%rcx)
	/*
	 * These trailing loads/stores have to do all their loads 1st,
	 * then do the stores.
	 */
L(P5Q0):
	mov    -0x5(%rdx),%r9d
	movzbq -0x1(%rdx),%r10
	mov    %r9d,-0x5(%rcx)
	mov    %r10b,-0x1(%rcx)
	ret   

	.balign 16               
L(P6QF):
	mov    -0x7e(%rdx),%r9
	mov    %r9,-0x7e(%rcx)
L(P6QE):
	mov    -0x76(%rdx),%r11
	mov    %r11,-0x76(%rcx)
L(P6QD):
	mov    -0x6e(%rdx),%r10
	mov    %r10,-0x6e(%rcx)
L(P6QC):
	mov    -0x66(%rdx),%r9
	mov    %r9,-0x66(%rcx)
L(P6QB):
	mov    -0x5e(%rdx),%r11
	mov    %r11,-0x5e(%rcx)
L(P6QA):
	mov    -0x56(%rdx),%r10
	mov    %r10,-0x56(%rcx)
L(P6Q9):
	mov    -0x4e(%rdx),%r9
	mov    %r9,-0x4e(%rcx)
L(P6Q8):
	mov    -0x46(%rdx),%r11
	mov    %r11,-0x46(%rcx)
L(P6Q7):
	mov    -0x3e(%rdx),%r10
	mov    %r10,-0x3e(%rcx)
L(P6Q6):
	mov    -0x36(%rdx),%r9
	mov    %r9,-0x36(%rcx)
L(P6Q5):
	mov    -0x2e(%rdx),%r11
	mov    %r11,-0x2e(%rcx)
L(P6Q4):
	mov    -0x26(%rdx),%r10
	mov    %r10,-0x26(%rcx)
L(P6Q3):
	mov    -0x1e(%rdx),%r9
	mov    %r9,-0x1e(%rcx)
L(P6Q2):
	mov    -0x16(%rdx),%r11
	mov    %r11,-0x16(%rcx)
L(P6Q1):
	mov    -0xe(%rdx),%r10
	mov    %r10,-0xe(%rcx)
	/*
	 * These trailing loads/stores have to do all their loads 1st,
	 * then do the stores.
	 */
L(P6Q0):
	mov    -0x6(%rdx),%r9d
	movzwq -0x2(%rdx),%r10
	mov    %r9d,-0x6(%rcx)
	mov    %r10w,-0x2(%rcx)
	ret   

	.balign 16               
L(P7QF):
	mov    -0x7f(%rdx),%r9
	mov    %r9,-0x7f(%rcx)
L(P7QE):
	mov    -0x77(%rdx),%r11
	mov    %r11,-0x77(%rcx)
L(P7QD):
	mov    -0x6f(%rdx),%r10
	mov    %r10,-0x6f(%rcx)
L(P7QC):
	mov    -0x67(%rdx),%r9
	mov    %r9,-0x67(%rcx)
L(P7QB):
	mov    -0x5f(%rdx),%r11
	mov    %r11,-0x5f(%rcx)
L(P7QA):
	mov    -0x57(%rdx),%r10
	mov    %r10,-0x57(%rcx)
L(P7Q9):
	mov    -0x4f(%rdx),%r9
	mov    %r9,-0x4f(%rcx)
L(P7Q8):
	mov    -0x47(%rdx),%r11
	mov    %r11,-0x47(%rcx)
L(P7Q7):
	mov    -0x3f(%rdx),%r10
	mov    %r10,-0x3f(%rcx)
L(P7Q6):
	mov    -0x37(%rdx),%r9
	mov    %r9,-0x37(%rcx)
L(P7Q5):
	mov    -0x2f(%rdx),%r11
	mov    %r11,-0x2f(%rcx)
L(P7Q4):
	mov    -0x27(%rdx),%r10
	mov    %r10,-0x27(%rcx)
L(P7Q3):
	mov    -0x1f(%rdx),%r9
	mov    %r9,-0x1f(%rcx)
L(P7Q2):
	mov    -0x17(%rdx),%r11
	mov    %r11,-0x17(%rcx)
L(P7Q1):
	mov    -0xf(%rdx),%r10
	mov    %r10,-0xf(%rcx)
	/*
	 * These trailing loads/stores have to do all their loads 1st,
	 * then do the stores.
	 */
L(P7Q0):
	mov    -0x7(%rdx),%r9d
	movzwq -0x3(%rdx),%r10
	movzbq -0x1(%rdx),%r11
	mov    %r9d,-0x7(%rcx)
	mov    %r10w,-0x3(%rcx)
	mov    %r11b,-0x1(%rcx)
	ret   

	.balign 16               
L(ck_use_sse2):
	/*
	 * Align dest to 16 byte boundary. 
	 */
	test   $0xf,%rcx
	jnz    L(ShrtAlignNew)

L(now_qw_aligned):
	cmpl   $NO_SSE,.memops_method(%rip) 
	je     L(Loop8byte_pre)

	/*
	 * The fall-through path is to do SSE2 16-byte load/stores
	 */

	/*
	 * If current move size is larger than half of the highest level cache
	 * size, then do non-temporal moves. 
	 */
	mov    .largest_level_cache_size(%rip),%r9d
	shr    %r9		# take half of it
	cmp    %r9,%r8  
	jg     L(sse2_nt_move)

	/*
	 * If both the source and dest are aligned, then use the both aligned
	 * logic. Well aligned data should reap the rewards.
	 */
	test   $0xf,%rdx
	jz     L(pre_both_aligned)

	lea    L(SSE_src)(%rip),%r10		# SSE2 (default)
	testl  $USE_SSSE3,.memops_method(%rip) 
	jz     1f
	lea    L(SSSE3_src)(%rip),%r10		# SSSE3

1:
	/*
	 * if the src is not 16 byte aligned...
	 */
	mov    %rdx,%r11
	and    $0xf,%r11
	movdqu (%rdx),%xmm0
	movdqa %xmm0,(%rcx)
	add    $0x10,%rdx
	sub    %r11,%rdx
	add    $0x10,%rcx
	sub    $0x10,%r8
	movdqa (%rdx),%xmm1

	movslq (%r10,%r11,4),%r9
	lea    (%r9,%r10,1),%r10
	jmpq   *%r10

	    .balign 16
L(SSSE3_src): .int	L(pre_both_aligned)-L(SSSE3_src)
	    .int        L(mov3dqa1) -L(SSSE3_src)
	    .int        L(mov3dqa2) -L(SSSE3_src)
	    .int        L(mov3dqa3) -L(SSSE3_src)
	    .int        L(mov3dqa4) -L(SSSE3_src)
	    .int        L(mov3dqa5) -L(SSSE3_src)
	    .int        L(mov3dqa6) -L(SSSE3_src)
	    .int        L(mov3dqa7) -L(SSSE3_src)
	    .int        L(movdqa8)  -L(SSSE3_src)
	    .int        L(mov3dqa9) -L(SSSE3_src)
	    .int        L(mov3dqa10)-L(SSSE3_src)
	    .int        L(mov3dqa11)-L(SSSE3_src) 
	    .int        L(mov3dqa12)-L(SSSE3_src)
	    .int        L(mov3dqa13)-L(SSSE3_src)
	    .int        L(mov3dqa14)-L(SSSE3_src)
	    .int        L(mov3dqa15)-L(SSSE3_src) 
L(SSE_src): .int    L(pre_both_aligned)-L(SSE_src)
	    .int        L(movdqa1) -L(SSE_src)
	    .int        L(movdqa2) -L(SSE_src)
	    .int        L(movdqa3) -L(SSE_src)
	    .int        L(movdqa4) -L(SSE_src)
	    .int        L(movdqa5) -L(SSE_src)
	    .int        L(movdqa6) -L(SSE_src)
	    .int        L(movdqa7) -L(SSE_src)
	    .int        L(movdqa8) -L(SSE_src)
	    .int        L(movdqa9) -L(SSE_src)
	    .int        L(movdqa10)-L(SSE_src)
	    .int        L(movdqa11)-L(SSE_src) 
	    .int        L(movdqa12)-L(SSE_src)
	    .int        L(movdqa13)-L(SSE_src)
	    .int        L(movdqa14)-L(SSE_src)
	    .int        L(movdqa15)-L(SSE_src) 

	.balign 16               
L(movdqa1):                                
	movdqa 0x10(%rdx),%xmm3 # load the upper source buffer
	movdqa 0x20(%rdx),%xmm0 # load the upper source buffer
	lea    0x20(%rdx),%rdx
	lea    -0x20(%r8),%r8

	psrldq $0x1,%xmm1  # shift right prev buffer (saved from last iteration)
	movdqa %xmm3,%xmm2 # store off xmm reg for use next iteration
	pslldq $0xf,%xmm3  # shift the current buffer left (shift in zeros)
	por    %xmm1,%xmm3 # OR them together
	cmp    $0x20,%r8

	psrldq $0x1,%xmm2  # shift right prev buffer (saved from last iteration)
	movdqa %xmm0,%xmm1 # store off xmm reg for use next iteration
	pslldq $0xf,%xmm0  # shift the current buffer left (shift in zeros)
	por    %xmm2,%xmm0 # OR them together
	movdqa %xmm3,(%rcx)     # store it
	movdqa %xmm0,0x10(%rcx) # store it
	lea    0x20(%rcx),%rcx

	jge    L(movdqa1)    
	jmp    L(movdqa_epi)       

	.balign 16               
L(movdqa2):                                
	sub    $0x20,%r8
	movdqa 0x10(%rdx),%xmm3
	movdqa 0x20(%rdx),%xmm0
	add    $0x20,%rdx

	psrldq $0x2,%xmm1
	movdqa %xmm3,%xmm2
	pslldq $0xe,%xmm3
	por    %xmm1,%xmm3

	psrldq $0x2,%xmm2
	movdqa %xmm0,%xmm1
	pslldq $0xe,%xmm0
	por    %xmm2,%xmm0
	movdqa %xmm3,(%rcx)
	movdqa %xmm0,0x10(%rcx)

	add    $0x20,%rcx
	cmp    $0x20,%r8
	jge    L(movdqa2)    
	jmp    L(movdqa_epi)       

	.balign 16               
L(movdqa3):                                
	sub    $0x20,%r8
	movdqa 0x10(%rdx),%xmm3
	movdqa 0x20(%rdx),%xmm0
	add    $0x20,%rdx

	psrldq $0x3,%xmm1
	movdqa %xmm3,%xmm2
	pslldq $0xd,%xmm3
	por    %xmm1,%xmm3

	psrldq $0x3,%xmm2
	movdqa %xmm0,%xmm1
	pslldq $0xd,%xmm0
	por    %xmm2,%xmm0
	movdqa %xmm3,(%rcx)
	movdqa %xmm0,0x10(%rcx)

	add    $0x20,%rcx
	cmp    $0x20,%r8
	jge    L(movdqa3)    
	jmp    L(movdqa_epi)       

	.balign 16               
L(movdqa4):                                
	sub    $0x20,%r8
	movdqa 0x10(%rdx),%xmm3
	movdqa 0x20(%rdx),%xmm0
	add    $0x20,%rdx

	psrldq $0x4,%xmm1
	movdqa %xmm3,%xmm2
	pslldq $0xc,%xmm3
	por    %xmm1,%xmm3

	psrldq $0x4,%xmm2
	movdqa %xmm0,%xmm1
	pslldq $0xc,%xmm0
	por    %xmm2,%xmm0

	movdqa %xmm3,(%rcx)
	movdqa %xmm0,0x10(%rcx)

	add    $0x20,%rcx
	cmp    $0x20,%r8
	jge    L(movdqa4)    
	jmp    L(movdqa_epi)       

	.balign 16               
L(movdqa5):                                
	sub    $0x20,%r8
	movdqa 0x10(%rdx),%xmm3
	movdqa 0x20(%rdx),%xmm0
	add    $0x20,%rdx

	psrldq $0x5,%xmm1
	movdqa %xmm3,%xmm2
	pslldq $0xb,%xmm3
	por    %xmm1,%xmm3

	psrldq $0x5,%xmm2
	movdqa %xmm0,%xmm1
	pslldq $0xb,%xmm0
	por    %xmm2,%xmm0

	movdqa %xmm3,(%rcx)
	movdqa %xmm0,0x10(%rcx)

	add    $0x20,%rcx
	cmp    $0x20,%r8
	jge    L(movdqa5)    
	jmp    L(movdqa_epi)       

	.balign 16               
L(movdqa6):                                
	sub    $0x20,%r8
	movdqa 0x10(%rdx),%xmm3
	movdqa 0x20(%rdx),%xmm0
	add    $0x20,%rdx

	psrldq $0x6,%xmm1
	movdqa %xmm3,%xmm2
	pslldq $0xa,%xmm3
	por    %xmm1,%xmm3

	psrldq $0x6,%xmm2
	movdqa %xmm0,%xmm1
	pslldq $0xa,%xmm0
	por    %xmm2,%xmm0
	movdqa %xmm3,(%rcx)
	movdqa %xmm0,0x10(%rcx)

	add    $0x20,%rcx
	cmp    $0x20,%r8
	jge    L(movdqa6)    
	jmp    L(movdqa_epi)       

	.balign 16               
L(movdqa7):                                
	sub    $0x20,%r8
	movdqa 0x10(%rdx),%xmm3
	movdqa 0x20(%rdx),%xmm0
	add    $0x20,%rdx

	psrldq $0x7,%xmm1
	movdqa %xmm3,%xmm2
	pslldq $0x9,%xmm3
	por    %xmm1,%xmm3

	psrldq $0x7,%xmm2
	movdqa %xmm0,%xmm1
	pslldq $0x9,%xmm0
	por    %xmm2,%xmm0
	movdqa %xmm3,(%rcx)
	movdqa %xmm0,0x10(%rcx)

	add    $0x20,%rcx
	cmp    $0x20,%r8
	jge    L(movdqa7)    
	jmp    L(movdqa_epi)       

	.balign 16               
L(movdqa8):                                
	movdqa 0x10(%rdx),%xmm3
	sub    $0x30,%r8
	movdqa 0x20(%rdx),%xmm0
	movdqa 0x30(%rdx),%xmm5
	lea    0x30(%rdx),%rdx

	shufpd $0x1,%xmm3,%xmm1
	movdqa %xmm1,(%rcx)

	cmp    $0x30,%r8

	shufpd $0x1,%xmm0,%xmm3
	movdqa %xmm3,0x10(%rcx)

	movdqa %xmm5,%xmm1
	shufpd $0x1,%xmm5,%xmm0
	movdqa %xmm0,0x20(%rcx)

	lea    0x30(%rcx),%rcx

	jge    L(movdqa8)
	jmp    L(movdqa_epi)

	.balign 16               
L(movdqa9):                                
	sub    $0x20,%r8
	movdqa 0x10(%rdx),%xmm3
	movdqa 0x20(%rdx),%xmm0
	add    $0x20,%rdx

	psrldq $0x9,%xmm1
	movdqa %xmm3,%xmm2
	pslldq $0x7,%xmm3
	por    %xmm1,%xmm3

	psrldq $0x9,%xmm2
	movdqa %xmm0,%xmm1
	pslldq $0x7,%xmm0
	por    %xmm2,%xmm0
	movdqa %xmm3,(%rcx)
	movdqa %xmm0,0x10(%rcx)

	add    $0x20,%rcx
	cmp    $0x20,%r8
	jge    L(movdqa9)    
	jmp    L(movdqa_epi)       

	.balign 16               
L(movdqa10):                               
	sub    $0x20,%r8
	movdqa 0x10(%rdx),%xmm3
	movdqa 0x20(%rdx),%xmm0
	add    $0x20,%rdx

	psrldq $0xa,%xmm1
	movdqa %xmm3,%xmm2
	pslldq $0x6,%xmm3
	por    %xmm1,%xmm3

	psrldq $0xa,%xmm2
	movdqa %xmm0,%xmm1
	pslldq $0x6,%xmm0
	por    %xmm2,%xmm0
	movdqa %xmm3,(%rcx)
	movdqa %xmm0,0x10(%rcx)

	add    $0x20,%rcx
	cmp    $0x20,%r8
	jge    L(movdqa10)   
	jmp    L(movdqa_epi)       

	.balign 16               
L(movdqa11):                               
	sub    $0x20,%r8
	movdqa 0x10(%rdx),%xmm3
	movdqa 0x20(%rdx),%xmm0
	add    $0x20,%rdx

	psrldq $0xb,%xmm1
	movdqa %xmm3,%xmm2
	pslldq $0x5,%xmm3
	por    %xmm1,%xmm3

	psrldq $0xb,%xmm2
	movdqa %xmm0,%xmm1
	pslldq $0x5,%xmm0
	por    %xmm2,%xmm0
	movdqa %xmm3,(%rcx)
	movdqa %xmm0,0x10(%rcx)

	add    $0x20,%rcx
	cmp    $0x20,%r8
	jge    L(movdqa11)   
	jmp    L(movdqa_epi)       

	.balign 16               
L(movdqa12):                               
	sub    $0x20,%r8
	movdqa 0x10(%rdx),%xmm3
	movdqa 0x20(%rdx),%xmm0
	add    $0x20,%rdx

	psrldq $0xc,%xmm1
	movdqa %xmm3,%xmm2
	pslldq $0x4,%xmm3
	por    %xmm1,%xmm3

	psrldq $0xc,%xmm2
	movdqa %xmm0,%xmm1
	pslldq $0x4,%xmm0
	por    %xmm2,%xmm0
	movdqa %xmm3,(%rcx)
	movdqa %xmm0,0x10(%rcx)

	add    $0x20,%rcx
	cmp    $0x20,%r8
	jge    L(movdqa12)   
	jmp    L(movdqa_epi)       

	.balign 16               
L(movdqa13):                               
	sub    $0x20,%r8
	movdqa 0x10(%rdx),%xmm3
	movdqa 0x20(%rdx),%xmm0
	add    $0x20,%rdx

	psrldq $0xd,%xmm1
	movdqa %xmm3,%xmm2
	pslldq $0x3,%xmm3
	por    %xmm1,%xmm3

	psrldq $0xd,%xmm2
	movdqa %xmm0,%xmm1
	pslldq $0x3,%xmm0
	por    %xmm2,%xmm0
	movdqa %xmm3,(%rcx)
	movdqa %xmm0,0x10(%rcx)

	add    $0x20,%rcx
	cmp    $0x20,%r8
	jge    L(movdqa13)   
	jmp    L(movdqa_epi)       

	.balign 16               
L(movdqa14):                               
	sub    $0x20,%r8
	movdqa 0x10(%rdx),%xmm3
	movdqa 0x20(%rdx),%xmm0
	add    $0x20,%rdx

	psrldq $0xe,%xmm1
	movdqa %xmm3,%xmm2
	pslldq $0x2,%xmm3
	por    %xmm1,%xmm3

	psrldq $0xe,%xmm2
	movdqa %xmm0,%xmm1
	pslldq $0x2,%xmm0
	por    %xmm2,%xmm0
	movdqa %xmm3,(%rcx)
	movdqa %xmm0,0x10(%rcx)

	add    $0x20,%rcx
	cmp    $0x20,%r8
	jge    L(movdqa14)   
	jmp    L(movdqa_epi)       

	.balign 16               
L(movdqa15):                               
	sub    $0x20,%r8
	movdqa 0x10(%rdx),%xmm3
	movdqa 0x20(%rdx),%xmm0
	add    $0x20,%rdx

	psrldq $0xf,%xmm1
	movdqa %xmm3,%xmm2
	pslldq $0x1,%xmm3
	por    %xmm1,%xmm3

	psrldq $0xf,%xmm2
	movdqa %xmm0,%xmm1
	pslldq $0x1,%xmm0
	por    %xmm2,%xmm0
	movdqa %xmm3,(%rcx)
	movdqa %xmm0,0x10(%rcx)

	add    $0x20,%rcx
	cmp    $0x20,%r8
	jge    L(movdqa15)   
	#jmp   L(movdqa_epi)

	.balign 16
L(movdqa_epi):                             
	lea    L(fwdPxQx)(%rip),%r10
	add    %r11,%rdx # bump rdx to the right addr (it lagged behind in the above loop)
	add    %r8,%rcx
	add    %r8,%rdx

	movslq (%r10,%r8,4),%r9
	lea    (%r9,%r10,1),%r10
	jmpq   *%r10

	.balign 16
L(mov3dqa1): 
	movdqa	0x10(%rdx),%xmm3 # load the upper source buffer
	sub	$0x30,%r8
	movdqa	0x20(%rdx),%xmm0 # load the upper source buffer
	movdqa	0x30(%rdx),%xmm5 # load the upper source buffer
	lea	0x30(%rdx),%rdx
	cmp	$0x30,%r8

	movdqa	%xmm3,%xmm2       # store off xmm reg for use next iteration
	#palignr	$0x1,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x01
	movdqa	%xmm3,(%rcx)      # store it

	movdqa	%xmm0,%xmm4       # store off xmm reg for use next iteration
	#palignr	$0x1,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x01
	movdqa	%xmm0,0x10(%rcx)  # store it

	movdqa	%xmm5,%xmm1       # store off xmm reg for use next iteration
	#palignr	$0x1,%xmm4,%xmm5
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xec,0x01
	movdqa	%xmm5,0x20(%rcx)  # store it

	lea	0x30(%rcx),%rcx
	jge	L(mov3dqa1)

	cmp	$0x10,%r8
	jl	L(movdqa_epi)
	movdqa	0x10(%rdx),%xmm3	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	movdqa	%xmm3,%xmm2		# save for use next concat
	#palignr	$0x1,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x01

	cmp	$0x10,%r8
	movdqa	%xmm3,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jl	L(movdqa_epi)

	movdqa	0x10(%rdx),%xmm0	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	#palignr	$0x1,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x01
	movdqa	%xmm0,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jmp	L(movdqa_epi)

	.balign 16
L(mov3dqa2): 
	movdqa	0x10(%rdx),%xmm3
	sub	$0x30,%r8
	movdqa	0x20(%rdx),%xmm0
	movdqa	0x30(%rdx),%xmm5
	lea	0x30(%rdx),%rdx
	cmp	$0x30,%r8

	movdqa	%xmm3,%xmm2
	#palignr	$0x2,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x02
	movdqa	%xmm3,(%rcx)

	movdqa	%xmm0,%xmm4
	#palignr	$0x2,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x02
	movdqa	%xmm0,0x10(%rcx)

	movdqa	%xmm5,%xmm1
	#palignr	$0x2,%xmm4,%xmm5
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xec,0x02
	movdqa	%xmm5,0x20(%rcx)

	lea	0x30(%rcx),%rcx
	jge	L(mov3dqa2)

	cmp	$0x10,%r8
	jl	L(movdqa_epi)
	movdqa	0x10(%rdx),%xmm3	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	movdqa	%xmm3,%xmm2		# save for use next concat
	#palignr	$0x2,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x02

	cmp	$0x10,%r8
	movdqa	%xmm3,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jl	L(movdqa_epi)

	movdqa	0x10(%rdx),%xmm0	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	#palignr	$0x2,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x02
	movdqa	%xmm0,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jmp	L(movdqa_epi)

	.balign 16
L(mov3dqa3): 
	movdqa	0x10(%rdx),%xmm3
	sub	$0x30,%r8
	movdqa	0x20(%rdx),%xmm0
	movdqa	0x30(%rdx),%xmm5
	lea	0x30(%rdx),%rdx
	cmp	$0x30,%r8

	movdqa	%xmm3,%xmm2
	#palignr	$0x3,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x03
	movdqa	%xmm3,(%rcx)

	movdqa	%xmm0,%xmm4
	#palignr	$0x3,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x03
	movdqa	%xmm0,0x10(%rcx)

	movdqa	%xmm5,%xmm1
	#palignr	$0x3,%xmm4,%xmm5
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xec,0x03
	movdqa	%xmm5,0x20(%rcx)

	lea	0x30(%rcx),%rcx
	jge	L(mov3dqa3)

	cmp	$0x10,%r8
	jl	L(movdqa_epi)
	movdqa	0x10(%rdx),%xmm3	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	movdqa	%xmm3,%xmm2		# save for use next concat
	#palignr	$0x3,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x03

	cmp	$0x10,%r8
	movdqa	%xmm3,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jl	L(movdqa_epi)

	movdqa	0x10(%rdx),%xmm0	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	#palignr	$0x3,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x03
	movdqa	%xmm0,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jmp	L(movdqa_epi)

	.balign 16
L(mov3dqa4): 
	movdqa	0x10(%rdx),%xmm3
	sub	$0x30,%r8
	movdqa	0x20(%rdx),%xmm0
	movdqa	0x30(%rdx),%xmm5
	lea	0x30(%rdx),%rdx
	cmp	$0x30,%r8

	movdqa	%xmm3,%xmm2
	#palignr	$0x4,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x04
	movdqa	%xmm3,(%rcx)

	movdqa	%xmm0,%xmm4
	#palignr	$0x4,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x04
	movdqa	%xmm0,0x10(%rcx)

	movdqa	%xmm5,%xmm1
	#palignr	$0x4,%xmm4,%xmm5
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xec,0x04
	movdqa	%xmm5,0x20(%rcx)

	lea	0x30(%rcx),%rcx
	jge	L(mov3dqa4)

	cmp	$0x10,%r8
	jl	L(movdqa_epi)
	movdqa	0x10(%rdx),%xmm3	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	movdqa	%xmm3,%xmm2		# save for use next concat
	#palignr	$0x4,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x04

	cmp	$0x10,%r8
	movdqa	%xmm3,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jl	L(movdqa_epi)

	movdqa	0x10(%rdx),%xmm0	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	#palignr	$0x4,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x04
	movdqa	%xmm0,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jmp	L(movdqa_epi)

	.balign 16
L(mov3dqa5): 
	movdqa	0x10(%rdx),%xmm3
	sub	$0x30,%r8
	movdqa	0x20(%rdx),%xmm0
	movdqa	0x30(%rdx),%xmm5
	lea	0x30(%rdx),%rdx
	cmp	$0x30,%r8

	movdqa	%xmm3,%xmm2
	#palignr	$0x5,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x05
	movdqa	%xmm3,(%rcx)

	movdqa	%xmm0,%xmm4
	#palignr	$0x5,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x05
	movdqa	%xmm0,0x10(%rcx)

	movdqa	%xmm5,%xmm1
	#palignr	$0x5,%xmm4,%xmm5
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xec,0x05
	movdqa	%xmm5,0x20(%rcx)

	lea	0x30(%rcx),%rcx
	jge	L(mov3dqa5)

	cmp	$0x10,%r8
	jl	L(movdqa_epi)
	movdqa	0x10(%rdx),%xmm3	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	movdqa	%xmm3,%xmm2		# save for use next concat
	#palignr	$0x5,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x05

	cmp	$0x10,%r8
	movdqa	%xmm3,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jl	L(movdqa_epi)

	movdqa	0x10(%rdx),%xmm0	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	#palignr	$0x5,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x05
	movdqa	%xmm0,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jmp	L(movdqa_epi)

	.balign 16
L(mov3dqa6): 
	movdqa	0x10(%rdx),%xmm3
	sub	$0x30,%r8
	movdqa	0x20(%rdx),%xmm0
	movdqa	0x30(%rdx),%xmm5
	lea	0x30(%rdx),%rdx
	cmp	$0x30,%r8

	movdqa	%xmm3,%xmm2
	#palignr	$0x6,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x06
	movdqa	%xmm3,(%rcx)

	movdqa	%xmm0,%xmm4
	#palignr	$0x6,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x06
	movdqa	%xmm0,0x10(%rcx)

	movdqa	%xmm5,%xmm1
	#palignr	$0x6,%xmm4,%xmm5
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xec,0x06
	movdqa	%xmm5,0x20(%rcx)

	lea	0x30(%rcx),%rcx
	jge	L(mov3dqa6)

	cmp	$0x10,%r8
	jl	L(movdqa_epi)
	movdqa	0x10(%rdx),%xmm3	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	movdqa	%xmm3,%xmm2		# save for use next concat
	#palignr	$0x6,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x06

	cmp	$0x10,%r8
	movdqa	%xmm3,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jl	L(movdqa_epi)

	movdqa	0x10(%rdx),%xmm0	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	#palignr	$0x6,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x06
	movdqa	%xmm0,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jmp	L(movdqa_epi)

	.balign 16
L(mov3dqa7): 
	movdqa	0x10(%rdx),%xmm3
	sub	$0x30,%r8
	movdqa	0x20(%rdx),%xmm0
	movdqa	0x30(%rdx),%xmm5
	lea	0x30(%rdx),%rdx
	cmp	$0x30,%r8

	movdqa	%xmm3,%xmm2
	#palignr	$0x7,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x07
	movdqa	%xmm3,(%rcx)

	movdqa	%xmm0,%xmm4
	#palignr	$0x7,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x07
	movdqa	%xmm0,0x10(%rcx)

	movdqa	%xmm5,%xmm1
	#palignr	$0x7,%xmm4,%xmm5
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xec,0x07
	movdqa	%xmm5,0x20(%rcx)

	lea	0x30(%rcx),%rcx
	jge	L(mov3dqa7)

	cmp	$0x10,%r8
	jl	L(movdqa_epi)
	movdqa	0x10(%rdx),%xmm3	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	movdqa	%xmm3,%xmm2		# save for use next concat
	#palignr	$0x7,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x07

	cmp	$0x10,%r8
	movdqa	%xmm3,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jl	L(movdqa_epi)

	movdqa	0x10(%rdx),%xmm0	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	#palignr	$0x7,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x07
	movdqa	%xmm0,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jmp	L(movdqa_epi)

	.balign 16
L(mov3dqa9): 
	movdqa	0x10(%rdx),%xmm3
	sub	$0x30,%r8
	movdqa	0x20(%rdx),%xmm0
	movdqa	0x30(%rdx),%xmm5
	lea	0x30(%rdx),%rdx
	cmp	$0x30,%r8

	movdqa	%xmm3,%xmm2
	#palignr	$0x9,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x09
	movdqa	%xmm3,(%rcx)

	movdqa	%xmm0,%xmm4
	#palignr	$0x9,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x09
	movdqa	%xmm0,0x10(%rcx)

	movdqa	%xmm5,%xmm1
	#palignr	$0x9,%xmm4,%xmm5
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xec,0x09
	movdqa	%xmm5,0x20(%rcx)

	lea	0x30(%rcx),%rcx
	jge	L(mov3dqa9)

	cmp	$0x10,%r8
	jl	L(movdqa_epi)
	movdqa	0x10(%rdx),%xmm3	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	movdqa	%xmm3,%xmm2		# save for use next concat
	#palignr	$0x9,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x09

	cmp	$0x10,%r8
	movdqa	%xmm3,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jl	L(movdqa_epi)

	movdqa	0x10(%rdx),%xmm0	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	#palignr	$0x9,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x09
	movdqa	%xmm0,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jmp	L(movdqa_epi)

	.balign 16
L(mov3dqa10): 
	movdqa	0x10(%rdx),%xmm3
	sub	$0x30,%r8
	movdqa	0x20(%rdx),%xmm0
	movdqa	0x30(%rdx),%xmm5
	lea	0x30(%rdx),%rdx
	cmp	$0x30,%r8

	movdqa	%xmm3,%xmm2
	#palignr	$0xa,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x0a
	movdqa	%xmm3,(%rcx)

	movdqa	%xmm0,%xmm4
	#palignr	$0xa,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x0a
	movdqa	%xmm0,0x10(%rcx)

	movdqa	%xmm5,%xmm1
	#palignr	$0xa,%xmm4,%xmm5
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xec,0x0a
	movdqa	%xmm5,0x20(%rcx)

	lea	0x30(%rcx),%rcx
	jge	L(mov3dqa10)

	cmp	$0x10,%r8
	jl	L(movdqa_epi)
	movdqa	0x10(%rdx),%xmm3	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	movdqa	%xmm3,%xmm2		# save for use next concat
	#palignr	$0xa,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x0a

	cmp	$0x10,%r8
	movdqa	%xmm3,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jl	L(movdqa_epi)

	movdqa	0x10(%rdx),%xmm0	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	#palignr	$0xa,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x0a
	movdqa	%xmm0,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jmp	L(movdqa_epi)

	.balign 16
L(mov3dqa11): 
	movdqa	0x10(%rdx),%xmm3
	sub	$0x30,%r8
	movdqa	0x20(%rdx),%xmm0
	movdqa	0x30(%rdx),%xmm5
	lea	0x30(%rdx),%rdx
	cmp	$0x30,%r8

	movdqa	%xmm3,%xmm2
	#palignr	$0xb,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x0b
	movdqa	%xmm3,(%rcx)

	movdqa	%xmm0,%xmm4
	#palignr	$0xb,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x0b
	movdqa	%xmm0,0x10(%rcx)

	movdqa	%xmm5,%xmm1
	#palignr	$0xb,%xmm4,%xmm5
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xec,0x0b
	movdqa	%xmm5,0x20(%rcx)

	lea	0x30(%rcx),%rcx
	jge	L(mov3dqa11)

	cmp	$0x10,%r8
	jl	L(movdqa_epi)
	movdqa	0x10(%rdx),%xmm3	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	movdqa	%xmm3,%xmm2		# save for use next concat
	#palignr	$0xb,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x0b

	cmp	$0x10,%r8
	movdqa	%xmm3,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jl	L(movdqa_epi)

	movdqa	0x10(%rdx),%xmm0	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	#palignr	$0xb,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x0b
	movdqa	%xmm0,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jmp	L(movdqa_epi)

	.balign 16
L(mov3dqa12): 
	movdqa	0x10(%rdx),%xmm3
	sub	$0x30,%r8
	movdqa	0x20(%rdx),%xmm0
	movdqa	0x30(%rdx),%xmm5
	lea	0x30(%rdx),%rdx
	cmp	$0x30,%r8

	movdqa	%xmm3,%xmm2
	#palignr	$0xc,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x0c
	movdqa	%xmm3,(%rcx)

	movdqa	%xmm0,%xmm4
	#palignr	$0xc,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x0c
	movdqa	%xmm0,0x10(%rcx)

	movdqa	%xmm5,%xmm1
	#palignr	$0xc,%xmm4,%xmm5
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xec,0x0c
	movdqa	%xmm5,0x20(%rcx)

	lea	0x30(%rcx),%rcx
	jge	L(mov3dqa12)

	cmp	$0x10,%r8
	jl	L(movdqa_epi)
	movdqa	0x10(%rdx),%xmm3	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	movdqa	%xmm3,%xmm2		# save for use next concat
	#palignr	$0xc,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x0c

	cmp	$0x10,%r8
	movdqa	%xmm3,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jl	L(movdqa_epi)

	movdqa	0x10(%rdx),%xmm0	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	#palignr	$0xc,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x0c
	movdqa	%xmm0,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jmp	L(movdqa_epi)

	.balign 16
L(mov3dqa13): 
	movdqa	0x10(%rdx),%xmm3
	sub	$0x30,%r8
	movdqa	0x20(%rdx),%xmm0
	movdqa	0x30(%rdx),%xmm5
	lea	0x30(%rdx),%rdx
	cmp	$0x30,%r8

	movdqa	%xmm3,%xmm2
	#palignr	$0xd,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x0d
	movdqa	%xmm3,(%rcx)

	movdqa	%xmm0,%xmm4
	#palignr	$0xd,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x0d
	movdqa	%xmm0,0x10(%rcx)

	movdqa	%xmm5,%xmm1
	#palignr	$0xd,%xmm4,%xmm5
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xec,0x0d
	movdqa	%xmm5,0x20(%rcx)

	lea	0x30(%rcx),%rcx
	jge	L(mov3dqa13)

	cmp	$0x10,%r8
	jl	L(movdqa_epi)
	movdqa	0x10(%rdx),%xmm3	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	movdqa	%xmm3,%xmm2		# save for use next concat
	#palignr	$0xd,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x0d

	cmp	$0x10,%r8
	movdqa	%xmm3,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jl	L(movdqa_epi)

	movdqa	0x10(%rdx),%xmm0	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	#palignr	$0xd,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x0d
	movdqa	%xmm0,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jmp	L(movdqa_epi)

	.balign 16
L(mov3dqa14): 
	movdqa	0x10(%rdx),%xmm3
	sub	$0x30,%r8
	movdqa	0x20(%rdx),%xmm0
	movdqa	0x30(%rdx),%xmm5
	lea	0x30(%rdx),%rdx
	cmp	$0x30,%r8

	movdqa	%xmm3,%xmm2
	#palignr	$0xe,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x0e
	movdqa	%xmm3,(%rcx)

	movdqa	%xmm0,%xmm4
	#palignr	$0xe,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x0e
	movdqa	%xmm0,0x10(%rcx)

	movdqa	%xmm5,%xmm1
	#palignr	$0xe,%xmm4,%xmm5
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xec,0x0e
	movdqa	%xmm5,0x20(%rcx)

	lea	0x30(%rcx),%rcx
	jge	L(mov3dqa14)

	cmp	$0x10,%r8
	jl	L(movdqa_epi)
	movdqa	0x10(%rdx),%xmm3	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	movdqa	%xmm3,%xmm2		# save for use next concat
	#palignr	$0xe,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x0e

	cmp	$0x10,%r8
	movdqa	%xmm3,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jl	L(movdqa_epi)

	movdqa	0x10(%rdx),%xmm0	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	#palignr	$0xe,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x0e
	movdqa	%xmm0,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jmp	L(movdqa_epi)

	.balign 16
L(mov3dqa15): 
	movdqa	0x10(%rdx),%xmm3
	sub	$0x30,%r8
	movdqa	0x20(%rdx),%xmm0
	movdqa	0x30(%rdx),%xmm5
	lea	0x30(%rdx),%rdx
	cmp	$0x30,%r8

	movdqa	%xmm3,%xmm2
	#palignr	$0xf,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x0f
	movdqa	%xmm3,(%rcx)

	movdqa	%xmm0,%xmm4
	#palignr	$0xf,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x0f
	movdqa	%xmm0,0x10(%rcx)

	movdqa	%xmm5,%xmm1
	#palignr	$0xf,%xmm4,%xmm5
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xec,0x0f
	movdqa	%xmm5,0x20(%rcx)

	lea	0x30(%rcx),%rcx
	jge	L(mov3dqa15)

	cmp	$0x10,%r8
	jl	L(movdqa_epi)
	movdqa	0x10(%rdx),%xmm3	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	movdqa	%xmm3,%xmm2		# save for use next concat
	#palignr	$0xf,%xmm1,%xmm3
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xd9,0x0f

	cmp	$0x10,%r8
	movdqa	%xmm3,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jl	L(movdqa_epi)

	movdqa	0x10(%rdx),%xmm0	# load the upper source buffer
	sub	$0x10,%r8
	lea	0x10(%rdx),%rdx
	#palignr	$0xf,%xmm2,%xmm0
	.byte	0x66,0x0f,0x3a,0x0f
	.byte	0xc2,0x0f
	movdqa	%xmm0,(%rcx)      	# store it
	lea	0x10(%rcx),%rcx
	jmp	L(movdqa_epi)

	.balign 16               
L(sse2_nt_move):                           
	lea	0x40(%rcx),%rcx
	lea	0x40(%rdx),%rdx
	lea	-0x40(%r8),%r8

	/*
	 * doesn't matter if source is aligned for stuff out of cache.
	 * the mis-aligned penalty is masked by the slowness of main memory.
	 */
	prefetchnta 0x180(%rdx)
	movdqu	-0x40(%rdx),%xmm0
	movdqu	-0x30(%rdx),%xmm1

	cmp	$0x40,%r8
	movntdq	%xmm0,-0x40(%rcx)
	movntdq	%xmm1,-0x30(%rcx)

	movdqu	-0x20(%rdx),%xmm2
	movdqu	-0x10(%rdx),%xmm3

	movntdq	%xmm2,-0x20(%rcx)
	movntdq	%xmm3,-0x10(%rcx)

	jge	L(sse2_nt_move) 

	lea	L(Fix16EndTable)(%rip),%r10 
	mov	%r8,%r9
	and	$0xFFFFFFFFFFFFFFF0,%r9
	add	%r9,%rcx
	add	%r9,%rdx
	sub	%r9,%r8
	shr	$0x4,%r9
	sfence 

	movslq	(%r10,%r9,4),%r11
	lea	(%r11,%r10,1),%r10
	jmpq	*%r10

	.balign 16
L(Fix16EndTable):
	.int    L(fix16_0)-L(Fix16EndTable)
	.int    L(fix16_1)-L(Fix16EndTable)
	.int    L(fix16_2)-L(Fix16EndTable)
	.int    L(fix16_3)-L(Fix16EndTable)

	.balign 16
L(fix16_3):                                
	movdqu -0x30(%rdx),%xmm1
	movdqa %xmm1,-0x30(%rcx)
L(fix16_2):                                
	movdqu -0x20(%rdx),%xmm2
	movdqa %xmm2,-0x20(%rcx)
L(fix16_1):                                
	movdqu -0x10(%rdx),%xmm3
	movdqa %xmm3,-0x10(%rcx)
L(fix16_0):                                
	lea    L(fwdPxQx)(%rip),%r10
	add    %r8,%rdx
	add    %r8,%rcx

	movslq (%r10,%r8,4),%r9
	lea    (%r9,%r10,1),%r10
	jmpq   *%r10

	.balign 16
L(pre_both_aligned):
	cmp    $0x80,%r8
	jl     L(fix_16b)

	.balign 16               
L(both_aligned):                           

	/*
	 * this 'paired' load/load/store/store seems to do best.
	 */
	movdqa (%rdx),%xmm0
	movdqa 0x10(%rdx),%xmm1

	movdqa %xmm0,(%rcx)
	movdqa %xmm1,0x10(%rcx)
	lea    -0x80(%r8),%r8

	movdqa 0x20(%rdx),%xmm2
	movdqa 0x30(%rdx),%xmm3

	movdqa %xmm2,0x20(%rcx)
	movdqa %xmm3,0x30(%rcx)

	movdqa 0x40(%rdx),%xmm0
	movdqa 0x50(%rdx),%xmm1
	cmp    $0x80,%r8

	movdqa %xmm0,0x40(%rcx)
	movdqa %xmm1,0x50(%rcx)

	movdqa 0x60(%rdx),%xmm2
	movdqa 0x70(%rdx),%xmm3
	lea    0x80(%rdx),%rdx
	movdqa %xmm2,0x60(%rcx)
	movdqa %xmm3,0x70(%rcx)
	lea    0x80(%rcx),%rcx
	jge    L(both_aligned) 

L(fix_16b):                                
	add    %r8,%rcx
	lea    L(fwdPxQx)(%rip),%r10
	add    %r8,%rdx

	movslq (%r10,%r8,4),%r9
	lea    (%r9,%r10,1),%r10
	jmpq   *%r10

	.balign 16
L(Loop8byte_pre):
	# Use 8-byte moves
	mov    .largest_level_cache_size(%rip),%r9d
	shr    %r9		# take half of it
	cmp    %r9,%r8  
	jg     L(byte8_nt_top)
	# Find out whether to use rep movsq
	cmp    $4096,%r8
	jle    L(byte8_top)
	mov    .amd64cache1half(%rip),%r9d	# half of l1 cache
	cmp    %r9,%r8
	jle    L(use_rep)

	.balign     16               
L(byte8_top):                              
	mov    (%rdx),%r9
	mov    0x8(%rdx),%r10
	lea    -0x40(%r8),%r8
	mov    %r9,(%rcx)
	mov    %r10,0x8(%rcx)
	mov    0x10(%rdx),%r11
	mov    0x18(%rdx),%r9
	mov    %r11,0x10(%rcx)
	mov    %r9,0x18(%rcx)

	cmp    $0x40,%r8
	mov    0x20(%rdx),%r10
	mov    0x28(%rdx),%r11
	mov    %r10,0x20(%rcx)
	mov    %r11,0x28(%rcx)
	mov    0x30(%rdx),%r9
	mov    0x38(%rdx),%r10
	lea    0x40(%rdx),%rdx
	mov    %r9,0x30(%rcx)
	mov    %r10,0x38(%rcx)
	lea    0x40(%rcx),%rcx
	jg     L(byte8_top)  

L(byte8_end):                              
	lea    L(fwdPxQx)(%rip),%r10
	lea    (%rdx,%r8,1),%rdx
	lea    (%rcx,%r8,1),%rcx

	movslq (%r10,%r8,4),%r9
	lea    (%r9,%r10,1),%r10
	jmpq   *%r10

	.balign	16
L(use_rep):
	mov    %rdx,%rsi		# %rsi = source
	mov    %rcx,%rdi		# %rdi = destination
	mov    %r8,%rcx			# %rcx = count
	shrq   $3,%rcx			# 8-byte word count
	rep
	  movsq
	mov    %rsi,%rdx		# source
	mov    %rdi,%rcx		# destination
	andq   $7,%r8			# remainder
	jnz    L(byte8_end)
	ret

	.balign 16               
L(byte8_nt_top):                           
	sub    $0x40,%r8
	prefetchnta 0x180(%rdx)
	mov    (%rdx),%r9
	movnti %r9,(%rcx)
	mov    0x8(%rdx),%r10
	movnti %r10,0x8(%rcx)
	mov    0x10(%rdx),%r11
	movnti %r11,0x10(%rcx)
	mov    0x18(%rdx),%r9
	movnti %r9,0x18(%rcx)
	mov    0x20(%rdx),%r10
	movnti %r10,0x20(%rcx)
	mov    0x28(%rdx),%r11
	movnti %r11,0x28(%rcx)
	mov    0x30(%rdx),%r9
	movnti %r9,0x30(%rcx)
	mov    0x38(%rdx),%r10
	movnti %r10,0x38(%rcx)

	lea    0x40(%rdx),%rdx
	lea    0x40(%rcx),%rcx
	cmp    $0x40,%r8
	jge    L(byte8_nt_top) 
	sfence
	jmp    L(byte8_end)        

	SET_SIZE(memcpy) 

	.balign 16
L(CopyBackwards):
	mov    %rdx,%r8
	mov    %rdi,%rcx
	mov    %rsi,%rdx
	mov    %rdi,%rax		# return value

	# ck alignment of last byte
	lea    (%rcx,%r8,1),%rcx
	test   $0x7,%rcx
	lea    (%rdx,%r8,1),%rdx
	jne    L(bk_align)

L(bk_qw_aligned):
	lea    L(bkPxQx)(%rip),%r10

	cmp    $0x90,%r8		# 144
	jg     L(bk_ck_sse2_alignment)

	sub    %r8,%rcx
	sub    %r8,%rdx

	movslq (%r10,%r8,4),%r9
	lea    (%r9,%r10,1),%r10
	jmpq   *%r10

	.balign 16
L(bk_align):
	# only align if len > 8
	cmp    $8,%r8
	jle    L(bk_qw_aligned)
	test   $0x1,%rcx
	je     L(bk_tst2)
	dec    %rcx
	dec    %rdx
	dec    %r8
	mov    (%rdx),%r9b
	mov    %r9b,(%rcx)

L(bk_tst2):
	test   $0x2,%rcx
	je     L(bk_tst3)

L(bk_got2):
	sub    $0x2,%rcx
	sub    $0x2,%rdx
	sub    $0x2,%r8
	movzwq (%rdx),%r9
	mov    %r9w,(%rcx)

L(bk_tst3):
	test   $0x4,%rcx
	je     L(bk_qw_aligned)

L(bk_got3):
	sub    $0x4,%rcx
	sub    $0x4,%rdx
	sub    $0x4,%r8
	mov    (%rdx),%r9d
	mov    %r9d,(%rcx)
	jmp    L(bk_qw_aligned)

	.balign 16
L(bk_ck_sse2_alignment):
	cmpl   $NO_SSE,.memops_method(%rip)
	je     L(bk_use_rep)
	# check alignment of last byte
	test   $0xf,%rcx
	jz     L(bk_sse2_cpy)

L(bk_sse2_align):
	# only here if already aligned on at least a qword bndry
	sub    $0x8,%rcx
	sub    $0x8,%rdx
	sub    $0x8,%r8
	mov    (%rdx),%r9
	mov    %r9,(%rcx)
	#jmp   L(bk_sse2_cpy)

	.balign 16
L(bk_sse2_cpy):
	sub    $0x80,%rcx		# 128
	sub    $0x80,%rdx
	movdqu 0x70(%rdx),%xmm3
	movdqu 0x60(%rdx),%xmm2
	movdqa %xmm3,0x70(%rcx)
	movdqa %xmm2,0x60(%rcx)
	sub    $0x80,%r8
	movdqu 0x50(%rdx),%xmm1
	movdqu 0x40(%rdx),%xmm0
	movdqa %xmm1,0x50(%rcx)
	movdqa %xmm0,0x40(%rcx)

	cmp    $0x80,%r8
	movdqu 0x30(%rdx),%xmm3
	movdqu 0x20(%rdx),%xmm2
	movdqa %xmm3,0x30(%rcx)
	movdqa %xmm2,0x20(%rcx)
	movdqu 0x10(%rdx),%xmm1
	movdqu (%rdx),%xmm0
	movdqa %xmm1,0x10(%rcx)
	movdqa %xmm0,(%rcx)
	jge    L(bk_sse2_cpy)

L(bk_sse2_cpy_end):
	lea    L(bkPxQx)(%rip),%r10
	sub    %r8,%rdx
	sub    %r8,%rcx
	movslq (%r10,%r8,4),%r9
	lea    (%r9,%r10,1),%r10
	jmpq   *%r10

	.balign 16
L(bk_use_rep):
	xchg   %rcx,%r9
	mov    %rdx,%rsi		# source
	mov    %r9,%rdi			# destination
	mov    %r8,%rcx			# count
	sub    $8,%rsi
	sub    $8,%rdi
	shr    $3,%rcx
	std				# reverse direction
	rep
	  movsq
	cld				# reset direction flag

	xchg   %rcx,%r9
	lea    L(bkPxQx)(%rip),%r10
	sub    %r8,%rdx
	sub    %r8,%rcx
	andq   $7,%r8			# remainder
	jz     2f
	movslq (%r10,%r8,4),%r9
	lea    (%r9,%r10,1),%r10
	jmpq   *%r10
2:
	ret

	.balign 16
L(bkP0QI):
	mov    0x88(%rdx),%r10
	mov    %r10,0x88(%rcx)
L(bkP0QH):
	mov    0x80(%rdx),%r10
	mov    %r10,0x80(%rcx)
L(bkP0QG):
	mov    0x78(%rdx),%r9
	mov    %r9,0x78(%rcx)
L(bkP0QF):
	mov    0x70(%rdx),%r11
	mov    %r11,0x70(%rcx)
L(bkP0QE):
	mov    0x68(%rdx),%r10
	mov    %r10,0x68(%rcx)
L(bkP0QD):
	mov    0x60(%rdx),%r9
	mov    %r9,0x60(%rcx)
L(bkP0QC):
	mov    0x58(%rdx),%r11
	mov    %r11,0x58(%rcx)
L(bkP0QB):
	mov    0x50(%rdx),%r10
	mov    %r10,0x50(%rcx)
L(bkP0QA):
	mov    0x48(%rdx),%r9
	mov    %r9,0x48(%rcx)
L(bkP0Q9):
	mov    0x40(%rdx),%r11
	mov    %r11,0x40(%rcx)
L(bkP0Q8):
	mov    0x38(%rdx),%r10
	mov    %r10,0x38(%rcx)
L(bkP0Q7):
	mov    0x30(%rdx),%r9
	mov    %r9,0x30(%rcx)
L(bkP0Q6):
	mov    0x28(%rdx),%r11
	mov    %r11,0x28(%rcx)
L(bkP0Q5):
	mov    0x20(%rdx),%r10
	mov    %r10,0x20(%rcx)
L(bkP0Q4):
	mov    0x18(%rdx),%r9
	mov    %r9,0x18(%rcx)
L(bkP0Q3):
	mov    0x10(%rdx),%r11
	mov    %r11,0x10(%rcx)
L(bkP0Q2):
	mov    0x8(%rdx),%r10
	mov    %r10,0x8(%rcx)
L(bkP0Q1):
	mov    (%rdx),%r9
	mov    %r9,(%rcx)
L(bkP0Q0):
	ret

	.balign 16
L(bkP1QI):
	mov    0x89(%rdx),%r10
	mov    %r10,0x89(%rcx)
L(bkP1QH):
	mov    0x81(%rdx),%r11
	mov    %r11,0x81(%rcx)
L(bkP1QG):
	mov    0x79(%rdx),%r10
	mov    %r10,0x79(%rcx)
L(bkP1QF):
	mov    0x71(%rdx),%r9
	mov    %r9,0x71(%rcx)
L(bkP1QE):
	mov    0x69(%rdx),%r11
	mov    %r11,0x69(%rcx)
L(bkP1QD):
	mov    0x61(%rdx),%r10
	mov    %r10,0x61(%rcx)
L(bkP1QC):
	mov    0x59(%rdx),%r9
	mov    %r9,0x59(%rcx)
L(bkP1QB):
	mov    0x51(%rdx),%r11
	mov    %r11,0x51(%rcx)
L(bkP1QA):
	mov    0x49(%rdx),%r10
	mov    %r10,0x49(%rcx)
L(bkP1Q9):
	mov    0x41(%rdx),%r9
	mov    %r9,0x41(%rcx)
L(bkP1Q8):
	mov    0x39(%rdx),%r11
	mov    %r11,0x39(%rcx)
L(bkP1Q7):
	mov    0x31(%rdx),%r10
	mov    %r10,0x31(%rcx)
L(bkP1Q6):
	mov    0x29(%rdx),%r9
	mov    %r9,0x29(%rcx)
L(bkP1Q5):
	mov    0x21(%rdx),%r11
	mov    %r11,0x21(%rcx)
L(bkP1Q4):
	mov    0x19(%rdx),%r10
	mov    %r10,0x19(%rcx)
L(bkP1Q3):
	mov    0x11(%rdx),%r9
	mov    %r9,0x11(%rcx)
L(bkP1Q2):
	mov    0x9(%rdx),%r11
	mov    %r11,0x9(%rcx)
L(bkP1Q1):
	mov    0x1(%rdx),%r10
	mov    %r10,0x1(%rcx)
L(bkP1Q0):
	mov    (%rdx),%r9b
	mov    %r9b,(%rcx)
	ret

	.balign 16
L(bkP2QI):
	mov    0x8a(%rdx),%r10
	mov    %r10,0x8a(%rcx)
L(bkP2QH):
	mov    0x82(%rdx),%r11
	mov    %r11,0x82(%rcx)
L(bkP2QG):
	mov    0x7a(%rdx),%r10
	mov    %r10,0x7a(%rcx)
L(bkP2QF):
	mov    0x72(%rdx),%r9
	mov    %r9,0x72(%rcx)
L(bkP2QE):
	mov    0x6a(%rdx),%r11
	mov    %r11,0x6a(%rcx)
L(bkP2QD):
	mov    0x62(%rdx),%r10
	mov    %r10,0x62(%rcx)
L(bkP2QC):
	mov    0x5a(%rdx),%r9
	mov    %r9,0x5a(%rcx)
L(bkP2QB):
	mov    0x52(%rdx),%r11
	mov    %r11,0x52(%rcx)
L(bkP2QA):
	mov    0x4a(%rdx),%r10
	mov    %r10,0x4a(%rcx)
L(bkP2Q9):
	mov    0x42(%rdx),%r9
	mov    %r9,0x42(%rcx)
L(bkP2Q8):
	mov    0x3a(%rdx),%r11
	mov    %r11,0x3a(%rcx)
L(bkP2Q7):
	mov    0x32(%rdx),%r10
	mov    %r10,0x32(%rcx)
L(bkP2Q6):
	mov    0x2a(%rdx),%r9
	mov    %r9,0x2a(%rcx)
L(bkP2Q5):
	mov    0x22(%rdx),%r11
	mov    %r11,0x22(%rcx)
L(bkP2Q4):
	mov    0x1a(%rdx),%r10
	mov    %r10,0x1a(%rcx)
L(bkP2Q3):
	mov    0x12(%rdx),%r9
	mov    %r9,0x12(%rcx)
L(bkP2Q2):
	mov    0xa(%rdx),%r11
	mov    %r11,0xa(%rcx)
L(bkP2Q1):
	mov    0x2(%rdx),%r10
	mov    %r10,0x2(%rcx)
L(bkP2Q0):
	mov    (%rdx),%r9w
	mov    %r9w,(%rcx)
	ret

	.balign 16
L(bkP3QI):
	mov    0x8b(%rdx),%r10
	mov    %r10,0x8b(%rcx)
L(bkP3QH):
	mov    0x83(%rdx),%r11
	mov    %r11,0x83(%rcx)
L(bkP3QG):
	mov    0x7b(%rdx),%r10
	mov    %r10,0x7b(%rcx)
L(bkP3QF):
	mov    0x73(%rdx),%r9
	mov    %r9,0x73(%rcx)
L(bkP3QE):
	mov    0x6b(%rdx),%r11
	mov    %r11,0x6b(%rcx)
L(bkP3QD):
	mov    0x63(%rdx),%r10
	mov    %r10,0x63(%rcx)
L(bkP3QC):
	mov    0x5b(%rdx),%r9
	mov    %r9,0x5b(%rcx)
L(bkP3QB):
	mov    0x53(%rdx),%r11
	mov    %r11,0x53(%rcx)
L(bkP3QA):
	mov    0x4b(%rdx),%r10
	mov    %r10,0x4b(%rcx)
L(bkP3Q9):
	mov    0x43(%rdx),%r9
	mov    %r9,0x43(%rcx)
L(bkP3Q8):
	mov    0x3b(%rdx),%r11
	mov    %r11,0x3b(%rcx)
L(bkP3Q7):
	mov    0x33(%rdx),%r10
	mov    %r10,0x33(%rcx)
L(bkP3Q6):
	mov    0x2b(%rdx),%r9
	mov    %r9,0x2b(%rcx)
L(bkP3Q5):
	mov    0x23(%rdx),%r11
	mov    %r11,0x23(%rcx)
L(bkP3Q4):
	mov    0x1b(%rdx),%r10
	mov    %r10,0x1b(%rcx)
L(bkP3Q3):
	mov    0x13(%rdx),%r9
	mov    %r9,0x13(%rcx)
L(bkP3Q2):
	mov    0xb(%rdx),%r11
	mov    %r11,0xb(%rcx)
L(bkP3Q1):
	mov    0x3(%rdx),%r10
	mov    %r10,0x3(%rcx)
L(bkP3Q0): # trailing loads/stores do all their loads 1st, then do the stores
	mov    0x1(%rdx),%r9w
	mov    %r9w,0x1(%rcx)
	mov    (%rdx),%r10b
	mov    %r10b,(%rcx)
	ret

	.balign 16
L(bkP4QI):
	mov    0x8c(%rdx),%r10
	mov    %r10,0x8c(%rcx)
L(bkP4QH):
	mov    0x84(%rdx),%r11
	mov    %r11,0x84(%rcx)
L(bkP4QG):
	mov    0x7c(%rdx),%r10
	mov    %r10,0x7c(%rcx)
L(bkP4QF):
	mov    0x74(%rdx),%r9
	mov    %r9,0x74(%rcx)
L(bkP4QE):
	mov    0x6c(%rdx),%r11
	mov    %r11,0x6c(%rcx)
L(bkP4QD):
	mov    0x64(%rdx),%r10
	mov    %r10,0x64(%rcx)
L(bkP4QC):
	mov    0x5c(%rdx),%r9
	mov    %r9,0x5c(%rcx)
L(bkP4QB):
	mov    0x54(%rdx),%r11
	mov    %r11,0x54(%rcx)
L(bkP4QA):
	mov    0x4c(%rdx),%r10
	mov    %r10,0x4c(%rcx)
L(bkP4Q9):
	mov    0x44(%rdx),%r9
	mov    %r9,0x44(%rcx)
L(bkP4Q8):
	mov    0x3c(%rdx),%r11
	mov    %r11,0x3c(%rcx)
L(bkP4Q7):
	mov    0x34(%rdx),%r10
	mov    %r10,0x34(%rcx)
L(bkP4Q6):
	mov    0x2c(%rdx),%r9
	mov    %r9,0x2c(%rcx)
L(bkP4Q5):
	mov    0x24(%rdx),%r11
	mov    %r11,0x24(%rcx)
L(bkP4Q4):
	mov    0x1c(%rdx),%r10
	mov    %r10,0x1c(%rcx)
L(bkP4Q3):
	mov    0x14(%rdx),%r9
	mov    %r9,0x14(%rcx)
L(bkP4Q2):
	mov    0xc(%rdx),%r11
	mov    %r11,0xc(%rcx)
L(bkP4Q1):
	mov    0x4(%rdx),%r10
	mov    %r10,0x4(%rcx)
L(bkP4Q0):
	mov    (%rdx),%r9d
	mov    %r9d,(%rcx)
	ret

	.balign 16
L(bkP5QI):
	mov    0x8d(%rdx),%r10
	mov    %r10,0x8d(%rcx)
L(bkP5QH):
	mov    0x85(%rdx),%r9
	mov    %r9,0x85(%rcx)
L(bkP5QG):
	mov    0x7d(%rdx),%r11
	mov    %r11,0x7d(%rcx)
L(bkP5QF):
	mov    0x75(%rdx),%r10
	mov    %r10,0x75(%rcx)
L(bkP5QE):
	mov    0x6d(%rdx),%r9
	mov    %r9,0x6d(%rcx)
L(bkP5QD):
	mov    0x65(%rdx),%r11
	mov    %r11,0x65(%rcx)
L(bkP5QC):
	mov    0x5d(%rdx),%r10
	mov    %r10,0x5d(%rcx)
L(bkP5QB):
	mov    0x55(%rdx),%r9
	mov    %r9,0x55(%rcx)
L(bkP5QA):
	mov    0x4d(%rdx),%r11
	mov    %r11,0x4d(%rcx)
L(bkP5Q9):
	mov    0x45(%rdx),%r10
	mov    %r10,0x45(%rcx)
L(bkP5Q8):
	mov    0x3d(%rdx),%r9
	mov    %r9,0x3d(%rcx)
L(bkP5Q7):
	mov    0x35(%rdx),%r11
	mov    %r11,0x35(%rcx)
L(bkP5Q6):
	mov    0x2d(%rdx),%r10
	mov    %r10,0x2d(%rcx)
L(bkP5Q5):
	mov    0x25(%rdx),%r9
	mov    %r9,0x25(%rcx)
L(bkP5Q4):
	mov    0x1d(%rdx),%r11
	mov    %r11,0x1d(%rcx)
L(bkP5Q3):
	mov    0x15(%rdx),%r10
	mov    %r10,0x15(%rcx)
L(bkP5Q2):
	mov    0xd(%rdx),%r9
	mov    %r9,0xd(%rcx)
L(bkP5Q1):
	mov    0x5(%rdx),%r11
	mov    %r11,0x5(%rcx)
L(bkP5Q0): # trailing loads/stores do all their loads 1st, then do the stores
	mov    0x1(%rdx),%r9d
	mov    %r9d,0x1(%rcx)
	mov    (%rdx),%r10b
	mov    %r10b,(%rcx)
	ret

	.balign 16
L(bkP6QI):
	mov    0x8e(%rdx),%r10
	mov    %r10,0x8e(%rcx)
L(bkP6QH):
	mov    0x86(%rdx),%r11
	mov    %r11,0x86(%rcx)
L(bkP6QG):
	mov    0x7e(%rdx),%r10
	mov    %r10,0x7e(%rcx)
L(bkP6QF):
	mov    0x76(%rdx),%r9
	mov    %r9,0x76(%rcx)
L(bkP6QE):
	mov    0x6e(%rdx),%r11
	mov    %r11,0x6e(%rcx)
L(bkP6QD):
	mov    0x66(%rdx),%r10
	mov    %r10,0x66(%rcx)
L(bkP6QC):
	mov    0x5e(%rdx),%r9
	mov    %r9,0x5e(%rcx)
L(bkP6QB):
	mov    0x56(%rdx),%r11
	mov    %r11,0x56(%rcx)
L(bkP6QA):
	mov    0x4e(%rdx),%r10
	mov    %r10,0x4e(%rcx)
L(bkP6Q9):
	mov    0x46(%rdx),%r9
	mov    %r9,0x46(%rcx)
L(bkP6Q8):
	mov    0x3e(%rdx),%r11
	mov    %r11,0x3e(%rcx)
L(bkP6Q7):
	mov    0x36(%rdx),%r10
	mov    %r10,0x36(%rcx)
L(bkP6Q6):
	mov    0x2e(%rdx),%r9
	mov    %r9,0x2e(%rcx)
L(bkP6Q5):
	mov    0x26(%rdx),%r11
	mov    %r11,0x26(%rcx)
L(bkP6Q4):
	mov    0x1e(%rdx),%r10
	mov    %r10,0x1e(%rcx)
L(bkP6Q3):
	mov    0x16(%rdx),%r9
	mov    %r9,0x16(%rcx)
L(bkP6Q2):
	mov    0xe(%rdx),%r11
	mov    %r11,0xe(%rcx)
L(bkP6Q1):
	mov    0x6(%rdx),%r10
	mov    %r10,0x6(%rcx)
L(bkP6Q0): # trailing loads/stores do all their loads 1st, then do the stores
	mov    0x2(%rdx),%r9d
	mov    %r9d,0x2(%rcx)
	mov    (%rdx),%r10w
	mov    %r10w,(%rcx)
	ret

	.balign 16
L(bkP7QI):
	mov    0x8f(%rdx),%r10
	mov    %r10,0x8f(%rcx)
L(bkP7QH):
	mov    0x87(%rdx),%r11
	mov    %r11,0x87(%rcx)
L(bkP7QG):
	mov    0x7f(%rdx),%r10
	mov    %r10,0x7f(%rcx)
L(bkP7QF):
	mov    0x77(%rdx),%r9
	mov    %r9,0x77(%rcx)
L(bkP7QE):
	mov    0x6f(%rdx),%r11
	mov    %r11,0x6f(%rcx)
L(bkP7QD):
	mov    0x67(%rdx),%r10
	mov    %r10,0x67(%rcx)
L(bkP7QC):
	mov    0x5f(%rdx),%r9
	mov    %r9,0x5f(%rcx)
L(bkP7QB):
	mov    0x57(%rdx),%r11
	mov    %r11,0x57(%rcx)
L(bkP7QA):
	mov    0x4f(%rdx),%r10
	mov    %r10,0x4f(%rcx)
L(bkP7Q9):
	mov    0x47(%rdx),%r9
	mov    %r9,0x47(%rcx)
L(bkP7Q8):
	mov    0x3f(%rdx),%r11
	mov    %r11,0x3f(%rcx)
L(bkP7Q7):
	mov    0x37(%rdx),%r10
	mov    %r10,0x37(%rcx)
L(bkP7Q6):
	mov    0x2f(%rdx),%r9
	mov    %r9,0x2f(%rcx)
L(bkP7Q5):
	mov    0x27(%rdx),%r11
	mov    %r11,0x27(%rcx)
L(bkP7Q4):
	mov    0x1f(%rdx),%r10
	mov    %r10,0x1f(%rcx)
L(bkP7Q3):
	mov    0x17(%rdx),%r9
	mov    %r9,0x17(%rcx)
L(bkP7Q2):
	mov    0xf(%rdx),%r11
	mov    %r11,0xf(%rcx)
L(bkP7Q1):
	mov    0x7(%rdx),%r10
	mov    %r10,0x7(%rcx)
L(bkP7Q0): # trailing loads/stores do all their loads 1st, then do the stores
	mov    0x3(%rdx),%r9d
	mov    %r9d,0x3(%rcx)
	mov    0x1(%rdx),%r10w
	mov    %r10w,0x1(%rcx)
	mov    (%rdx),%r11b
	mov    %r11b,(%rcx)
	ret

		.balign 16
L(bkPxQx):	.int L(bkP0Q0)-L(bkPxQx)
		.int L(bkP1Q0)-L(bkPxQx)
		.int L(bkP2Q0)-L(bkPxQx)
		.int L(bkP3Q0)-L(bkPxQx)
		.int L(bkP4Q0)-L(bkPxQx)
		.int L(bkP5Q0)-L(bkPxQx)
		.int L(bkP6Q0)-L(bkPxQx)
		.int L(bkP7Q0)-L(bkPxQx)

		.int L(bkP0Q1)-L(bkPxQx)
		.int L(bkP1Q1)-L(bkPxQx)
		.int L(bkP2Q1)-L(bkPxQx)
		.int L(bkP3Q1)-L(bkPxQx)
		.int L(bkP4Q1)-L(bkPxQx)
		.int L(bkP5Q1)-L(bkPxQx)
		.int L(bkP6Q1)-L(bkPxQx)
		.int L(bkP7Q1)-L(bkPxQx)

		.int L(bkP0Q2)-L(bkPxQx)
		.int L(bkP1Q2)-L(bkPxQx)
		.int L(bkP2Q2)-L(bkPxQx)
		.int L(bkP3Q2)-L(bkPxQx)
		.int L(bkP4Q2)-L(bkPxQx)
		.int L(bkP5Q2)-L(bkPxQx)
		.int L(bkP6Q2)-L(bkPxQx)
		.int L(bkP7Q2)-L(bkPxQx)

		.int L(bkP0Q3)-L(bkPxQx)
		.int L(bkP1Q3)-L(bkPxQx)
		.int L(bkP2Q3)-L(bkPxQx)
		.int L(bkP3Q3)-L(bkPxQx)
		.int L(bkP4Q3)-L(bkPxQx)
		.int L(bkP5Q3)-L(bkPxQx)
		.int L(bkP6Q3)-L(bkPxQx)
		.int L(bkP7Q3)-L(bkPxQx)

		.int L(bkP0Q4)-L(bkPxQx)
		.int L(bkP1Q4)-L(bkPxQx)
		.int L(bkP2Q4)-L(bkPxQx)
		.int L(bkP3Q4)-L(bkPxQx)
		.int L(bkP4Q4)-L(bkPxQx)
		.int L(bkP5Q4)-L(bkPxQx)
		.int L(bkP6Q4)-L(bkPxQx)
		.int L(bkP7Q4)-L(bkPxQx)

		.int L(bkP0Q5)-L(bkPxQx)
		.int L(bkP1Q5)-L(bkPxQx)
		.int L(bkP2Q5)-L(bkPxQx)
		.int L(bkP3Q5)-L(bkPxQx)
		.int L(bkP4Q5)-L(bkPxQx)
		.int L(bkP5Q5)-L(bkPxQx)
		.int L(bkP6Q5)-L(bkPxQx)
		.int L(bkP7Q5)-L(bkPxQx)

		.int L(bkP0Q6)-L(bkPxQx)
		.int L(bkP1Q6)-L(bkPxQx)
		.int L(bkP2Q6)-L(bkPxQx)
		.int L(bkP3Q6)-L(bkPxQx)
		.int L(bkP4Q6)-L(bkPxQx)
		.int L(bkP5Q6)-L(bkPxQx)
		.int L(bkP6Q6)-L(bkPxQx)
		.int L(bkP7Q6)-L(bkPxQx)

		.int L(bkP0Q7)-L(bkPxQx)
		.int L(bkP1Q7)-L(bkPxQx)
		.int L(bkP2Q7)-L(bkPxQx)
		.int L(bkP3Q7)-L(bkPxQx)
		.int L(bkP4Q7)-L(bkPxQx)
		.int L(bkP5Q7)-L(bkPxQx)
		.int L(bkP6Q7)-L(bkPxQx)
		.int L(bkP7Q7)-L(bkPxQx)

		.int L(bkP0Q8)-L(bkPxQx)
		.int L(bkP1Q8)-L(bkPxQx)
		.int L(bkP2Q8)-L(bkPxQx)
		.int L(bkP3Q8)-L(bkPxQx)
		.int L(bkP4Q8)-L(bkPxQx)
		.int L(bkP5Q8)-L(bkPxQx)
		.int L(bkP6Q8)-L(bkPxQx)
		.int L(bkP7Q8)-L(bkPxQx)

		.int L(bkP0Q9)-L(bkPxQx)
		.int L(bkP1Q9)-L(bkPxQx)
		.int L(bkP2Q9)-L(bkPxQx)
		.int L(bkP3Q9)-L(bkPxQx)
		.int L(bkP4Q9)-L(bkPxQx)
		.int L(bkP5Q9)-L(bkPxQx)
		.int L(bkP6Q9)-L(bkPxQx)
		.int L(bkP7Q9)-L(bkPxQx)

		.int L(bkP0QA)-L(bkPxQx)
		.int L(bkP1QA)-L(bkPxQx)
		.int L(bkP2QA)-L(bkPxQx)
		.int L(bkP3QA)-L(bkPxQx)
		.int L(bkP4QA)-L(bkPxQx)
		.int L(bkP5QA)-L(bkPxQx)
		.int L(bkP6QA)-L(bkPxQx)
		.int L(bkP7QA)-L(bkPxQx)

		.int L(bkP0QB)-L(bkPxQx)
		.int L(bkP1QB)-L(bkPxQx)
		.int L(bkP2QB)-L(bkPxQx)
		.int L(bkP3QB)-L(bkPxQx)
		.int L(bkP4QB)-L(bkPxQx)
		.int L(bkP5QB)-L(bkPxQx)
		.int L(bkP6QB)-L(bkPxQx)
		.int L(bkP7QB)-L(bkPxQx)

		.int L(bkP0QC)-L(bkPxQx)
		.int L(bkP1QC)-L(bkPxQx)
		.int L(bkP2QC)-L(bkPxQx)
		.int L(bkP3QC)-L(bkPxQx)
		.int L(bkP4QC)-L(bkPxQx)
		.int L(bkP5QC)-L(bkPxQx)
		.int L(bkP6QC)-L(bkPxQx)
		.int L(bkP7QC)-L(bkPxQx)

		.int L(bkP0QD)-L(bkPxQx)
		.int L(bkP1QD)-L(bkPxQx)
		.int L(bkP2QD)-L(bkPxQx)
		.int L(bkP3QD)-L(bkPxQx)
		.int L(bkP4QD)-L(bkPxQx)
		.int L(bkP5QD)-L(bkPxQx)
		.int L(bkP6QD)-L(bkPxQx)
		.int L(bkP7QD)-L(bkPxQx)

		.int L(bkP0QE)-L(bkPxQx)
		.int L(bkP1QE)-L(bkPxQx)
		.int L(bkP2QE)-L(bkPxQx)
		.int L(bkP3QE)-L(bkPxQx)
		.int L(bkP4QE)-L(bkPxQx)
		.int L(bkP5QE)-L(bkPxQx)
		.int L(bkP6QE)-L(bkPxQx)
		.int L(bkP7QE)-L(bkPxQx)

		.int L(bkP0QF)-L(bkPxQx)
		.int L(bkP1QF)-L(bkPxQx)
		.int L(bkP2QF)-L(bkPxQx)
		.int L(bkP3QF)-L(bkPxQx)
		.int L(bkP4QF)-L(bkPxQx)
		.int L(bkP5QF)-L(bkPxQx)
		.int L(bkP6QF)-L(bkPxQx)
		.int L(bkP7QF)-L(bkPxQx)

		.int L(bkP0QG)-L(bkPxQx)
		.int L(bkP1QG)-L(bkPxQx)
		.int L(bkP2QG)-L(bkPxQx)
		.int L(bkP3QG)-L(bkPxQx)
		.int L(bkP4QG)-L(bkPxQx)
		.int L(bkP5QG)-L(bkPxQx)
		.int L(bkP6QG)-L(bkPxQx)
		.int L(bkP7QG)-L(bkPxQx)

		.int L(bkP0QH)-L(bkPxQx)
		.int L(bkP1QH)-L(bkPxQx)
		.int L(bkP2QH)-L(bkPxQx)
		.int L(bkP3QH)-L(bkPxQx)
		.int L(bkP4QH)-L(bkPxQx)
		.int L(bkP5QH)-L(bkPxQx)
		.int L(bkP6QH)-L(bkPxQx)
		.int L(bkP7QH)-L(bkPxQx)

		.int L(bkP0QI)-L(bkPxQx)
		.int L(bkP1QI)-L(bkPxQx)
		.int L(bkP2QI)-L(bkPxQx)
		.int L(bkP3QI)-L(bkPxQx)
		.int L(bkP4QI)-L(bkPxQx)
		.int L(bkP5QI)-L(bkPxQx)
		.int L(bkP6QI)-L(bkPxQx)
		.int L(bkP7QI)-L(bkPxQx)

	SET_SIZE(memmove)
