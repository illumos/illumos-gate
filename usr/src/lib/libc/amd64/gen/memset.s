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
 * Copyright (c) 2008, Intel Corporation
 * All rights reserved.
 */
		.ident	"%Z%%M%	%I%	%E% SMI"

		.file	"%M%"

#include <sys/asm_linkage.h>

		ANSI_PRAGMA_WEAK(memset,function)

#include "synonyms.h"
#include "cache.h"
#include "proc64_id.h"

#define L(s) .memset/**/s

/*
 * memset algorithm overview:
 *
 * Thresholds used below were determined experimentally.
 *
 * Pseudo code:
 *
 * If (size <= 144 bytes) {
 *	do unrolled code (primarily 8-byte stores) regardless of alignment.
 * } else {
 *	Align destination to 16-byte boundary
 *
 *      if (NO_SSE) {
 *		If (size > largest level cache) {
 *			Use 8-byte non-temporal stores (64-bytes/loop)
 *		} else {
 *			if (size >= 2K) {
 *				Use rep sstoq
 *			} else {
 *				Use 8-byte stores (128 bytes per loop)
 *			}
 *		}
 *
 *	} else { **USE SSE**
 *		If (size <= 192 bytes) {
 *			do unrolled code using primarily 16-byte stores (SSE2)
 *		} else {
 *			If (size > largest level cache) {
 *				Use 16-byte non-temporal stores (128-bytes/loop)
 *			} else {
 *				Use 16-byte stores (128 bytes per loop)
 *			}
 *		}
 *	}
 *
 *	Finish any remaining bytes via unrolled code above.
 * }
 */

		ENTRY(memset)		# (void *, const void*, size_t)
		cmp    $0x1,%rdx
		mov    %rdi,%rax	# memset returns the dest address
		jne    L(ck2)
		mov    %sil,(%rdi)
		ret
L(ck2):                                    
		mov    $0x0101010101010101,%r9
		mov    %rdx,%r8
		movzbq %sil,%rdx
		imul   %r9,%rdx		# clone value 8 times

		cmp    $0x90,%r8	# 144
		jge    L(ck_align)

		lea    L(setPxQx)(%rip),%r11
		add    %r8,%rdi

		movslq (%r11,%r8,4),%rcx
		lea    (%rcx,%r11,1),%r11
		jmpq   *%r11

		.balign 16
L(setPxQx):	.int       L(P0Q0)-L(setPxQx)
		.int       L(P1Q0)-L(setPxQx)
		.int       L(P2Q0)-L(setPxQx)
		.int       L(P3Q0)-L(setPxQx)
		.int       L(P4Q0)-L(setPxQx)
		.int       L(P5Q0)-L(setPxQx)
		.int       L(P6Q0)-L(setPxQx)
		.int       L(P7Q0)-L(setPxQx) 

		.int       L(P0Q1)-L(setPxQx)
		.int       L(P1Q1)-L(setPxQx)
		.int       L(P2Q1)-L(setPxQx)
		.int       L(P3Q1)-L(setPxQx)
		.int       L(P4Q1)-L(setPxQx)
		.int       L(P5Q1)-L(setPxQx)
		.int       L(P6Q1)-L(setPxQx)
		.int       L(P7Q1)-L(setPxQx) 

		.int       L(P0Q2)-L(setPxQx)
		.int       L(P1Q2)-L(setPxQx)
		.int       L(P2Q2)-L(setPxQx)
		.int       L(P3Q2)-L(setPxQx)
		.int       L(P4Q2)-L(setPxQx)
		.int       L(P5Q2)-L(setPxQx)
		.int       L(P6Q2)-L(setPxQx)
		.int       L(P7Q2)-L(setPxQx) 

		.int       L(P0Q3)-L(setPxQx)
		.int       L(P1Q3)-L(setPxQx)
		.int       L(P2Q3)-L(setPxQx)
		.int       L(P3Q3)-L(setPxQx)
		.int       L(P4Q3)-L(setPxQx)
		.int       L(P5Q3)-L(setPxQx)
		.int       L(P6Q3)-L(setPxQx)
		.int       L(P7Q3)-L(setPxQx) 

		.int       L(P0Q4)-L(setPxQx)
		.int       L(P1Q4)-L(setPxQx)
		.int       L(P2Q4)-L(setPxQx)
		.int       L(P3Q4)-L(setPxQx)
		.int       L(P4Q4)-L(setPxQx)
		.int       L(P5Q4)-L(setPxQx)
		.int       L(P6Q4)-L(setPxQx)
		.int       L(P7Q4)-L(setPxQx) 

		.int       L(P0Q5)-L(setPxQx)
		.int       L(P1Q5)-L(setPxQx)
		.int       L(P2Q5)-L(setPxQx)
		.int       L(P3Q5)-L(setPxQx)
		.int       L(P4Q5)-L(setPxQx)
		.int       L(P5Q5)-L(setPxQx)
		.int       L(P6Q5)-L(setPxQx)
		.int       L(P7Q5)-L(setPxQx) 

		.int       L(P0Q6)-L(setPxQx)
		.int       L(P1Q6)-L(setPxQx)
		.int       L(P2Q6)-L(setPxQx)
		.int       L(P3Q6)-L(setPxQx)
		.int       L(P4Q6)-L(setPxQx)
		.int       L(P5Q6)-L(setPxQx)
		.int       L(P6Q6)-L(setPxQx)
		.int       L(P7Q6)-L(setPxQx) 

		.int       L(P0Q7)-L(setPxQx)
		.int       L(P1Q7)-L(setPxQx)
		.int       L(P2Q7)-L(setPxQx)
		.int       L(P3Q7)-L(setPxQx)
		.int       L(P4Q7)-L(setPxQx)
		.int       L(P5Q7)-L(setPxQx)
		.int       L(P6Q7)-L(setPxQx)
		.int       L(P7Q7)-L(setPxQx) 

		.int       L(P0Q8)-L(setPxQx)
		.int       L(P1Q8)-L(setPxQx)
		.int       L(P2Q8)-L(setPxQx)
		.int       L(P3Q8)-L(setPxQx)
		.int       L(P4Q8)-L(setPxQx)
		.int       L(P5Q8)-L(setPxQx)
		.int       L(P6Q8)-L(setPxQx)
		.int       L(P7Q8)-L(setPxQx) 

		.int       L(P0Q9)-L(setPxQx)
		.int       L(P1Q9)-L(setPxQx)
		.int       L(P2Q9)-L(setPxQx)
		.int       L(P3Q9)-L(setPxQx)
		.int       L(P4Q9)-L(setPxQx)
		.int       L(P5Q9)-L(setPxQx)
		.int       L(P6Q9)-L(setPxQx)
		.int       L(P7Q9)-L(setPxQx) 

		.int       L(P0QA)-L(setPxQx)
		.int       L(P1QA)-L(setPxQx)
		.int       L(P2QA)-L(setPxQx)
		.int       L(P3QA)-L(setPxQx)
		.int       L(P4QA)-L(setPxQx)
		.int       L(P5QA)-L(setPxQx)
		.int       L(P6QA)-L(setPxQx)
		.int       L(P7QA)-L(setPxQx)

		.int       L(P0QB)-L(setPxQx)
		.int       L(P1QB)-L(setPxQx)
		.int       L(P2QB)-L(setPxQx)
		.int       L(P3QB)-L(setPxQx)
		.int       L(P4QB)-L(setPxQx)
		.int       L(P5QB)-L(setPxQx)
		.int       L(P6QB)-L(setPxQx)
		.int       L(P7QB)-L(setPxQx)

		.int       L(P0QC)-L(setPxQx)
		.int       L(P1QC)-L(setPxQx)
		.int       L(P2QC)-L(setPxQx)
		.int       L(P3QC)-L(setPxQx)
		.int       L(P4QC)-L(setPxQx)
		.int       L(P5QC)-L(setPxQx)
		.int       L(P6QC)-L(setPxQx)
		.int       L(P7QC)-L(setPxQx)

		.int       L(P0QD)-L(setPxQx)
		.int       L(P1QD)-L(setPxQx)
		.int       L(P2QD)-L(setPxQx)
		.int       L(P3QD)-L(setPxQx)
		.int       L(P4QD)-L(setPxQx)
		.int       L(P5QD)-L(setPxQx)
		.int       L(P6QD)-L(setPxQx)
		.int       L(P7QD)-L(setPxQx)

		.int       L(P0QE)-L(setPxQx)	# 112
		.int       L(P1QE)-L(setPxQx)
		.int       L(P2QE)-L(setPxQx)
		.int       L(P3QE)-L(setPxQx)
		.int       L(P4QE)-L(setPxQx)
		.int       L(P5QE)-L(setPxQx)
		.int       L(P6QE)-L(setPxQx)
		.int       L(P7QE)-L(setPxQx) 

		.int       L(P0QF)-L(setPxQx)	#120
		.int       L(P1QF)-L(setPxQx)
		.int       L(P2QF)-L(setPxQx)
		.int       L(P3QF)-L(setPxQx)
		.int       L(P4QF)-L(setPxQx)
		.int       L(P5QF)-L(setPxQx)
		.int       L(P6QF)-L(setPxQx)
		.int       L(P7QF)-L(setPxQx) 

		.int       L(P0QG)-L(setPxQx)	#128
		.int       L(P1QG)-L(setPxQx)
		.int       L(P2QG)-L(setPxQx)
		.int       L(P3QG)-L(setPxQx)
		.int       L(P4QG)-L(setPxQx)
		.int       L(P5QG)-L(setPxQx)
		.int       L(P6QG)-L(setPxQx)
		.int       L(P7QG)-L(setPxQx) 

		.int       L(P0QH)-L(setPxQx)	#136
		.int       L(P1QH)-L(setPxQx)
		.int       L(P2QH)-L(setPxQx)
		.int       L(P3QH)-L(setPxQx)
		.int       L(P4QH)-L(setPxQx)
		.int       L(P5QH)-L(setPxQx)
		.int       L(P6QH)-L(setPxQx)
		.int       L(P7QH)-L(setPxQx)	#143

		.balign 16
L(P1QH):	mov    %rdx,-0x89(%rdi)
L(P1QG):	mov    %rdx,-0x81(%rdi)
		.balign 16
L(P1QF):	mov    %rdx,-0x79(%rdi)
L(P1QE):	mov    %rdx,-0x71(%rdi)
L(P1QD):	mov    %rdx,-0x69(%rdi)
L(P1QC):	mov    %rdx,-0x61(%rdi)
L(P1QB):	mov    %rdx,-0x59(%rdi)
L(P1QA):	mov    %rdx,-0x51(%rdi)
L(P1Q9):	mov    %rdx,-0x49(%rdi)
L(P1Q8):	mov    %rdx,-0x41(%rdi)
L(P1Q7):	mov    %rdx,-0x39(%rdi)
L(P1Q6):	mov    %rdx,-0x31(%rdi)
L(P1Q5):	mov    %rdx,-0x29(%rdi)
L(P1Q4):	mov    %rdx,-0x21(%rdi)
L(P1Q3):	mov    %rdx,-0x19(%rdi)
L(P1Q2):	mov    %rdx,-0x11(%rdi)
L(P1Q1):	mov    %rdx,-0x9(%rdi)
L(P1Q0):	mov    %dl,-0x1(%rdi)
		ret

		.balign 16
L(P0QH):	mov    %rdx,-0x88(%rdi)
		.balign 16
L(P0QG):	mov    %rdx,-0x80(%rdi)
L(P0QF):	mov    %rdx,-0x78(%rdi)
L(P0QE):	mov    %rdx,-0x70(%rdi)
L(P0QD):	mov    %rdx,-0x68(%rdi)
L(P0QC):	mov    %rdx,-0x60(%rdi)
L(P0QB):	mov    %rdx,-0x58(%rdi)
L(P0QA):	mov    %rdx,-0x50(%rdi)
L(P0Q9):	mov    %rdx,-0x48(%rdi)
L(P0Q8):	mov    %rdx,-0x40(%rdi)
L(P0Q7):	mov    %rdx,-0x38(%rdi)
L(P0Q6):	mov    %rdx,-0x30(%rdi)
L(P0Q5):	mov    %rdx,-0x28(%rdi)
L(P0Q4):	mov    %rdx,-0x20(%rdi)
L(P0Q3):	mov    %rdx,-0x18(%rdi)
L(P0Q2):	mov    %rdx,-0x10(%rdi)
L(P0Q1):	mov    %rdx,-0x8(%rdi)
L(P0Q0):	ret

		.balign 16
L(P2QH):	mov    %rdx,-0x8a(%rdi)
L(P2QG):	mov    %rdx,-0x82(%rdi)
		.balign 16
L(P2QF):	mov    %rdx,-0x7a(%rdi)
L(P2QE):	mov    %rdx,-0x72(%rdi)
L(P2QD):	mov    %rdx,-0x6a(%rdi)
L(P2QC):	mov    %rdx,-0x62(%rdi)
L(P2QB):	mov    %rdx,-0x5a(%rdi)
L(P2QA):	mov    %rdx,-0x52(%rdi)
L(P2Q9):	mov    %rdx,-0x4a(%rdi)
L(P2Q8):	mov    %rdx,-0x42(%rdi)
L(P2Q7):	mov    %rdx,-0x3a(%rdi)
L(P2Q6):	mov    %rdx,-0x32(%rdi)
L(P2Q5):	mov    %rdx,-0x2a(%rdi)
L(P2Q4):	mov    %rdx,-0x22(%rdi)
L(P2Q3):	mov    %rdx,-0x1a(%rdi)
L(P2Q2):	mov    %rdx,-0x12(%rdi)
L(P2Q1):	mov    %rdx,-0xa(%rdi)
L(P2Q0):	mov    %dx,-0x2(%rdi)
		ret

		.balign 16
L(P3QH):	mov    %rdx,-0x8b(%rdi)
L(P3QG):	mov    %rdx,-0x83(%rdi)
		.balign 16
L(P3QF):	mov    %rdx,-0x7b(%rdi)
L(P3QE):	mov    %rdx,-0x73(%rdi)
L(P3QD):	mov    %rdx,-0x6b(%rdi)
L(P3QC):	mov    %rdx,-0x63(%rdi)
L(P3QB):	mov    %rdx,-0x5b(%rdi)
L(P3QA):	mov    %rdx,-0x53(%rdi)
L(P3Q9):	mov    %rdx,-0x4b(%rdi)
L(P3Q8):	mov    %rdx,-0x43(%rdi)
L(P3Q7):	mov    %rdx,-0x3b(%rdi)
L(P3Q6):	mov    %rdx,-0x33(%rdi)
L(P3Q5):	mov    %rdx,-0x2b(%rdi)
L(P3Q4):	mov    %rdx,-0x23(%rdi)
L(P3Q3):	mov    %rdx,-0x1b(%rdi)
L(P3Q2):	mov    %rdx,-0x13(%rdi)
L(P3Q1):	mov    %rdx,-0xb(%rdi)
L(P3Q0):	mov    %dx,-0x3(%rdi)
		mov    %dl,-0x1(%rdi)
		ret

		.balign 16
L(P4QH):	mov    %rdx,-0x8c(%rdi)
L(P4QG):	mov    %rdx,-0x84(%rdi)
		.balign 16
L(P4QF):	mov    %rdx,-0x7c(%rdi)
L(P4QE):	mov    %rdx,-0x74(%rdi)
L(P4QD):	mov    %rdx,-0x6c(%rdi)
L(P4QC):	mov    %rdx,-0x64(%rdi)
L(P4QB):	mov    %rdx,-0x5c(%rdi)
L(P4QA):	mov    %rdx,-0x54(%rdi)
L(P4Q9):	mov    %rdx,-0x4c(%rdi)
L(P4Q8):	mov    %rdx,-0x44(%rdi)
L(P4Q7):	mov    %rdx,-0x3c(%rdi)
L(P4Q6):	mov    %rdx,-0x34(%rdi)
L(P4Q5):	mov    %rdx,-0x2c(%rdi)
L(P4Q4):	mov    %rdx,-0x24(%rdi)
L(P4Q3):	mov    %rdx,-0x1c(%rdi)
L(P4Q2):	mov    %rdx,-0x14(%rdi)
L(P4Q1):	mov    %rdx,-0xc(%rdi)
L(P4Q0):	mov    %edx,-0x4(%rdi)
		ret

		.balign 16
L(P5QH):	mov    %rdx,-0x8d(%rdi)
L(P5QG):	mov    %rdx,-0x85(%rdi)
		.balign 16
L(P5QF):	mov    %rdx,-0x7d(%rdi)
L(P5QE):	mov    %rdx,-0x75(%rdi)
L(P5QD):	mov    %rdx,-0x6d(%rdi)
L(P5QC):	mov    %rdx,-0x65(%rdi)
L(P5QB):	mov    %rdx,-0x5d(%rdi)
L(P5QA):	mov    %rdx,-0x55(%rdi)
L(P5Q9):	mov    %rdx,-0x4d(%rdi)
L(P5Q8):	mov    %rdx,-0x45(%rdi)
L(P5Q7):	mov    %rdx,-0x3d(%rdi)
L(P5Q6):	mov    %rdx,-0x35(%rdi)
L(P5Q5):	mov    %rdx,-0x2d(%rdi)
L(P5Q4):	mov    %rdx,-0x25(%rdi)
L(P5Q3):	mov    %rdx,-0x1d(%rdi)
L(P5Q2):	mov    %rdx,-0x15(%rdi)
L(P5Q1):	mov    %rdx,-0xd(%rdi)
L(P5Q0):	mov    %edx,-0x5(%rdi)
		mov    %dl,-0x1(%rdi)
		ret

		.balign 16
L(P6QH):	mov    %rdx,-0x8e(%rdi)
L(P6QG):	mov    %rdx,-0x86(%rdi)
		.balign 16
L(P6QF):	mov    %rdx,-0x7e(%rdi)
L(P6QE):	mov    %rdx,-0x76(%rdi)
L(P6QD):	mov    %rdx,-0x6e(%rdi)
L(P6QC):	mov    %rdx,-0x66(%rdi)
L(P6QB):	mov    %rdx,-0x5e(%rdi)
L(P6QA):	mov    %rdx,-0x56(%rdi)
L(P6Q9):	mov    %rdx,-0x4e(%rdi)
L(P6Q8):	mov    %rdx,-0x46(%rdi)
L(P6Q7):	mov    %rdx,-0x3e(%rdi)
L(P6Q6):	mov    %rdx,-0x36(%rdi)
L(P6Q5):	mov    %rdx,-0x2e(%rdi)
L(P6Q4):	mov    %rdx,-0x26(%rdi)
L(P6Q3):	mov    %rdx,-0x1e(%rdi)
L(P6Q2):	mov    %rdx,-0x16(%rdi)
L(P6Q1):	mov    %rdx,-0xe(%rdi)
L(P6Q0):	mov    %edx,-0x6(%rdi)
		mov    %dx,-0x2(%rdi)
		ret

		.balign 16
L(P7QH):	mov    %rdx,-0x8f(%rdi)
L(P7QG):	mov    %rdx,-0x87(%rdi)
		.balign 16
L(P7QF):	mov    %rdx,-0x7f(%rdi)
L(P7QE):	mov    %rdx,-0x77(%rdi)
L(P7QD):	mov    %rdx,-0x6f(%rdi)
L(P7QC):	mov    %rdx,-0x67(%rdi)
L(P7QB):	mov    %rdx,-0x5f(%rdi)
L(P7QA):	mov    %rdx,-0x57(%rdi)
L(P7Q9):	mov    %rdx,-0x4f(%rdi)
L(P7Q8):	mov    %rdx,-0x47(%rdi)
L(P7Q7):	mov    %rdx,-0x3f(%rdi)
L(P7Q6):	mov    %rdx,-0x37(%rdi)
L(P7Q5):	mov    %rdx,-0x2f(%rdi)
L(P7Q4):	mov    %rdx,-0x27(%rdi)
L(P7Q3):	mov    %rdx,-0x1f(%rdi)
L(P7Q2):	mov    %rdx,-0x17(%rdi)
L(P7Q1):	mov    %rdx,-0xf(%rdi)
L(P7Q0):	mov    %edx,-0x7(%rdi)
		mov    %dx,-0x3(%rdi)
		mov    %dl,-0x1(%rdi)
		ret

		.balign 16
L(ck_align):                      
		/* 
		 * Align to 16 byte boundary first
		 */
	 	lea    L(AliPxQx)(%rip),%r11
	 	mov    $0x10,%r10
	 	mov    %rdi,%r9
	 	and    $0xf,%r9
	 	sub    %r9,%r10
	 	and    $0xf,%r10
	 	add    %r10,%rdi
	 	sub    %r10,%r8

		movslq (%r11,%r10,4),%rcx
		lea    (%rcx,%r11,1),%r11
		jmpq   *%r11			# align dest to 16-byte boundary

		.balign 16
L(AliPxQx):	.int	L(aligned_now)-L(AliPxQx)
		.int	L(A1Q0)-L(AliPxQx)
		.int	L(A2Q0)-L(AliPxQx)
		.int	L(A3Q0)-L(AliPxQx)
		.int	L(A4Q0)-L(AliPxQx)
		.int	L(A5Q0)-L(AliPxQx)
		.int	L(A6Q0)-L(AliPxQx)
		.int	L(A7Q0)-L(AliPxQx)

		.int	L(A0Q1)-L(AliPxQx)
		.int	L(A1Q1)-L(AliPxQx)
		.int	L(A2Q1)-L(AliPxQx)
		.int	L(A3Q1)-L(AliPxQx)
		.int	L(A4Q1)-L(AliPxQx)
		.int	L(A5Q1)-L(AliPxQx)
		.int	L(A6Q1)-L(AliPxQx)
		.int	L(A7Q1)-L(AliPxQx)

		.balign 16
L(A5Q1):	mov    %dl,-0xd(%rdi)
L(A4Q1):	mov    %edx,-0xc(%rdi)
L(A0Q1):	mov    %rdx,-0x8(%rdi)
		jmp     L(aligned_now)

		.balign 16
L(A1Q1):	mov    %dl,-0x9(%rdi)
		mov    %rdx,-0x8(%rdi)
		jmp    L(aligned_now)

		.balign 16
L(A1Q0):	mov    %dl,-0x1(%rdi)
		jmp    L(aligned_now)

		.balign 16
L(A3Q1):	mov    %dl,-0xb(%rdi)
L(A2Q1):	mov    %dx,-0xa(%rdi)
		mov    %rdx,-0x8(%rdi)
		jmp    L(aligned_now)

		.balign 16
L(A3Q0):	mov    %dl,-0x3(%rdi)
L(A2Q0):	mov    %dx,-0x2(%rdi)
		jmp    L(aligned_now)

		.balign 16
L(A5Q0):	mov    %dl,-0x5(%rdi)
L(A4Q0):	mov    %edx,-0x4(%rdi)
		jmp    L(aligned_now)

		.balign 16
L(A7Q1):	mov    %dl,-0xf(%rdi)
L(A6Q1):	mov    %dx,-0xe(%rdi)
		mov    %edx,-0xc(%rdi)
		mov    %rdx,-0x8(%rdi)
		jmp    L(aligned_now)

		.balign 16
L(A7Q0):	mov    %dl,-0x7(%rdi)
L(A6Q0):	mov    %dx,-0x6(%rdi)
		mov    %edx,-0x4(%rdi)
		#jmp    L(aligned_now)		# Fall thru...

		.balign 16
L(aligned_now):
		/*
		 * Check memops method
		 */
		cmpl   $NO_SSE,.memops_method(%rip)
		je     L(Loop8byte_pre)

		/*
		 * Use SSE2 instructions
		 */
	 	movd   %rdx,%xmm0
		lea    L(SSExDx)(%rip),%r9	# after dest alignment
	 	punpcklqdq %xmm0,%xmm0		# fill RegXMM0 with the pattern
		cmp    $0xc0,%r8		# 192
		jge    L(byte32sse2_pre)

		add    %r8,%rdi

		movslq (%r9,%r8,4),%rcx
		lea    (%rcx,%r9,1),%r9
		jmpq   *%r9

		.balign 16
L(SSE0QB):	movdqa %xmm0,-0xb0(%rdi)
L(SSE0QA):	movdqa %xmm0,-0xa0(%rdi)
L(SSE0Q9):	movdqa %xmm0,-0x90(%rdi)
L(SSE0Q8):	movdqa %xmm0,-0x80(%rdi)
L(SSE0Q7):	movdqa %xmm0,-0x70(%rdi)
L(SSE0Q6):	movdqa %xmm0,-0x60(%rdi)
L(SSE0Q5):	movdqa %xmm0,-0x50(%rdi)
L(SSE0Q4):	movdqa %xmm0,-0x40(%rdi)
L(SSE0Q3):	movdqa %xmm0,-0x30(%rdi)
L(SSE0Q2):	movdqa %xmm0,-0x20(%rdi)
L(SSE0Q1):	movdqa %xmm0,-0x10(%rdi)
L(SSE0Q0):	ret

		.balign 16
L(SSE1QB):	movdqa %xmm0,-0xb1(%rdi)
L(SSE1QA):	movdqa %xmm0,-0xa1(%rdi)
L(SSE1Q9):	movdqa %xmm0,-0x91(%rdi)
L(SSE1Q8):	movdqa %xmm0,-0x81(%rdi)
L(SSE1Q7):	movdqa %xmm0,-0x71(%rdi)
L(SSE1Q6):	movdqa %xmm0,-0x61(%rdi)
L(SSE1Q5):	movdqa %xmm0,-0x51(%rdi)
L(SSE1Q4):	movdqa %xmm0,-0x41(%rdi)
L(SSE1Q3):	movdqa %xmm0,-0x31(%rdi)
L(SSE1Q2):	movdqa %xmm0,-0x21(%rdi)
L(SSE1Q1):	movdqa %xmm0,-0x11(%rdi)
L(SSE1Q0):	mov    %dl,-0x1(%rdi)
		ret

		.balign 16
L(SSE2QB):	movdqa %xmm0,-0xb2(%rdi)
L(SSE2QA):	movdqa %xmm0,-0xa2(%rdi)
L(SSE2Q9):	movdqa %xmm0,-0x92(%rdi)
L(SSE2Q8):	movdqa %xmm0,-0x82(%rdi)
L(SSE2Q7):	movdqa %xmm0,-0x72(%rdi)
L(SSE2Q6):	movdqa %xmm0,-0x62(%rdi)
L(SSE2Q5):	movdqa %xmm0,-0x52(%rdi)
L(SSE2Q4):	movdqa %xmm0,-0x42(%rdi)
L(SSE2Q3):	movdqa %xmm0,-0x32(%rdi)
L(SSE2Q2):	movdqa %xmm0,-0x22(%rdi)
L(SSE2Q1):	movdqa %xmm0,-0x12(%rdi)
L(SSE2Q0):	mov    %dx,-0x2(%rdi)
		ret

		.balign 16
L(SSE3QB):	movdqa %xmm0,-0xb3(%rdi)
L(SSE3QA):	movdqa %xmm0,-0xa3(%rdi)
L(SSE3Q9):	movdqa %xmm0,-0x93(%rdi)
L(SSE3Q8):	movdqa %xmm0,-0x83(%rdi)
L(SSE3Q7):	movdqa %xmm0,-0x73(%rdi)
L(SSE3Q6):	movdqa %xmm0,-0x63(%rdi)
L(SSE3Q5):	movdqa %xmm0,-0x53(%rdi)
L(SSE3Q4):	movdqa %xmm0,-0x43(%rdi)
L(SSE3Q3):	movdqa %xmm0,-0x33(%rdi)
L(SSE3Q2):	movdqa %xmm0,-0x23(%rdi)
L(SSE3Q1):	movdqa %xmm0,-0x13(%rdi)
L(SSE3Q0):	mov    %dx,-0x3(%rdi)
		mov    %dl,-0x1(%rdi)
		ret

		.balign 16
L(SSE4QB):	movdqa %xmm0,-0xb4(%rdi)
L(SSE4QA):	movdqa %xmm0,-0xa4(%rdi)
L(SSE4Q9):	movdqa %xmm0,-0x94(%rdi)
L(SSE4Q8):	movdqa %xmm0,-0x84(%rdi)
L(SSE4Q7):	movdqa %xmm0,-0x74(%rdi)
L(SSE4Q6):	movdqa %xmm0,-0x64(%rdi)
L(SSE4Q5):	movdqa %xmm0,-0x54(%rdi)
L(SSE4Q4):	movdqa %xmm0,-0x44(%rdi)
L(SSE4Q3):	movdqa %xmm0,-0x34(%rdi)
L(SSE4Q2):	movdqa %xmm0,-0x24(%rdi)
L(SSE4Q1):	movdqa %xmm0,-0x14(%rdi)
L(SSE4Q0):	mov    %edx,-0x4(%rdi)
		ret

		.balign 16
L(SSE5QB):	movdqa %xmm0,-0xb5(%rdi)
L(SSE5QA):	movdqa %xmm0,-0xa5(%rdi)
L(SSE5Q9):	movdqa %xmm0,-0x95(%rdi)
L(SSE5Q8):	movdqa %xmm0,-0x85(%rdi)
L(SSE5Q7):	movdqa %xmm0,-0x75(%rdi)
L(SSE5Q6):	movdqa %xmm0,-0x65(%rdi)
L(SSE5Q5):	movdqa %xmm0,-0x55(%rdi)
L(SSE5Q4):	movdqa %xmm0,-0x45(%rdi)
L(SSE5Q3):	movdqa %xmm0,-0x35(%rdi)
L(SSE5Q2):	movdqa %xmm0,-0x25(%rdi)
L(SSE5Q1):	movdqa %xmm0,-0x15(%rdi)
L(SSE5Q0):	mov    %edx,-0x5(%rdi)
		mov    %dl,-0x1(%rdi)
		ret

		.balign 16
L(SSE6QB):	movdqa %xmm0,-0xb6(%rdi)
L(SSE6QA):	movdqa %xmm0,-0xa6(%rdi)
L(SSE6Q9):	movdqa %xmm0,-0x96(%rdi)
L(SSE6Q8):	movdqa %xmm0,-0x86(%rdi)
L(SSE6Q7):	movdqa %xmm0,-0x76(%rdi)
L(SSE6Q6):	movdqa %xmm0,-0x66(%rdi)
L(SSE6Q5):	movdqa %xmm0,-0x56(%rdi)
L(SSE6Q4):	movdqa %xmm0,-0x46(%rdi)
L(SSE6Q3):	movdqa %xmm0,-0x36(%rdi)
L(SSE6Q2):	movdqa %xmm0,-0x26(%rdi)
L(SSE6Q1):	movdqa %xmm0,-0x16(%rdi)
L(SSE6Q0):	mov    %edx,-0x6(%rdi)
		mov    %dx,-0x2(%rdi)
		ret

		.balign 16
L(SSE7QB):	movdqa %xmm0,-0xb7(%rdi)
L(SSE7QA):	movdqa %xmm0,-0xa7(%rdi)
L(SSE7Q9):	movdqa %xmm0,-0x97(%rdi)
L(SSE7Q8):	movdqa %xmm0,-0x87(%rdi)
L(SSE7Q7):	movdqa %xmm0,-0x77(%rdi)
L(SSE7Q6):	movdqa %xmm0,-0x67(%rdi)
L(SSE7Q5):	movdqa %xmm0,-0x57(%rdi)
L(SSE7Q4):	movdqa %xmm0,-0x47(%rdi)
L(SSE7Q3):	movdqa %xmm0,-0x37(%rdi)
L(SSE7Q2):	movdqa %xmm0,-0x27(%rdi)
L(SSE7Q1):	movdqa %xmm0,-0x17(%rdi)
L(SSE7Q0):	mov    %edx,-0x7(%rdi)
		mov    %dx,-0x3(%rdi)
		mov    %dl,-0x1(%rdi)
		ret

		.balign 16
L(SSE8QB):	movdqa %xmm0,-0xb8(%rdi)
L(SSE8QA):	movdqa %xmm0,-0xa8(%rdi)
L(SSE8Q9):	movdqa %xmm0,-0x98(%rdi)
L(SSE8Q8):	movdqa %xmm0,-0x88(%rdi)
L(SSE8Q7):	movdqa %xmm0,-0x78(%rdi)
L(SSE8Q6):	movdqa %xmm0,-0x68(%rdi)
L(SSE8Q5):	movdqa %xmm0,-0x58(%rdi)
L(SSE8Q4):	movdqa %xmm0,-0x48(%rdi)
L(SSE8Q3):	movdqa %xmm0,-0x38(%rdi)
L(SSE8Q2):	movdqa %xmm0,-0x28(%rdi)
L(SSE8Q1):	movdqa %xmm0,-0x18(%rdi)
L(SSE8Q0):	mov    %rdx,-0x8(%rdi)
		ret

		.balign 16
L(SSE9QB):	movdqa %xmm0,-0xb9(%rdi)
L(SSE9QA):	movdqa %xmm0,-0xa9(%rdi)
L(SSE9Q9):	movdqa %xmm0,-0x99(%rdi)
L(SSE9Q8):	movdqa %xmm0,-0x89(%rdi)
L(SSE9Q7):	movdqa %xmm0,-0x79(%rdi)
L(SSE9Q6):	movdqa %xmm0,-0x69(%rdi)
L(SSE9Q5):	movdqa %xmm0,-0x59(%rdi)
L(SSE9Q4):	movdqa %xmm0,-0x49(%rdi)
L(SSE9Q3):	movdqa %xmm0,-0x39(%rdi)
L(SSE9Q2):	movdqa %xmm0,-0x29(%rdi)
L(SSE9Q1):	movdqa %xmm0,-0x19(%rdi)
L(SSE9Q0):	mov    %rdx,-0x9(%rdi)
		mov    %dl,-0x1(%rdi)
		ret

		.balign 16
L(SSE10QB):	movdqa %xmm0,-0xba(%rdi)
L(SSE10QA):	movdqa %xmm0,-0xaa(%rdi)
L(SSE10Q9):	movdqa %xmm0,-0x9a(%rdi)
L(SSE10Q8):	movdqa %xmm0,-0x8a(%rdi)
L(SSE10Q7):	movdqa %xmm0,-0x7a(%rdi)
L(SSE10Q6):	movdqa %xmm0,-0x6a(%rdi)
L(SSE10Q5):	movdqa %xmm0,-0x5a(%rdi)
L(SSE10Q4):	movdqa %xmm0,-0x4a(%rdi)
L(SSE10Q3):	movdqa %xmm0,-0x3a(%rdi)
L(SSE10Q2):	movdqa %xmm0,-0x2a(%rdi)
L(SSE10Q1):	movdqa %xmm0,-0x1a(%rdi)
L(SSE10Q0):	mov    %rdx,-0xa(%rdi)
		mov    %dx,-0x2(%rdi)
		ret

		.balign 16
L(SSE11QB):	movdqa %xmm0,-0xbb(%rdi)
L(SSE11QA):	movdqa %xmm0,-0xab(%rdi)
L(SSE11Q9):	movdqa %xmm0,-0x9b(%rdi)
L(SSE11Q8):	movdqa %xmm0,-0x8b(%rdi)
L(SSE11Q7):	movdqa %xmm0,-0x7b(%rdi)
L(SSE11Q6):	movdqa %xmm0,-0x6b(%rdi)
L(SSE11Q5):	movdqa %xmm0,-0x5b(%rdi)
L(SSE11Q4):	movdqa %xmm0,-0x4b(%rdi)
L(SSE11Q3):	movdqa %xmm0,-0x3b(%rdi)
L(SSE11Q2):	movdqa %xmm0,-0x2b(%rdi)
L(SSE11Q1):	movdqa %xmm0,-0x1b(%rdi)
L(SSE11Q0):	mov    %rdx,-0xb(%rdi)
		mov    %dx,-0x3(%rdi)
		mov    %dl,-0x1(%rdi)
		ret

		.balign 16
L(SSE12QB):	movdqa %xmm0,-0xbc(%rdi)
L(SSE12QA):	movdqa %xmm0,-0xac(%rdi)
L(SSE12Q9):	movdqa %xmm0,-0x9c(%rdi)
L(SSE12Q8):	movdqa %xmm0,-0x8c(%rdi)
L(SSE12Q7):	movdqa %xmm0,-0x7c(%rdi)
L(SSE12Q6):	movdqa %xmm0,-0x6c(%rdi)
L(SSE12Q5):	movdqa %xmm0,-0x5c(%rdi)
L(SSE12Q4):	movdqa %xmm0,-0x4c(%rdi)
L(SSE12Q3):	movdqa %xmm0,-0x3c(%rdi)
L(SSE12Q2):	movdqa %xmm0,-0x2c(%rdi)
L(SSE12Q1):	movdqa %xmm0,-0x1c(%rdi)
L(SSE12Q0):	mov    %rdx,-0xc(%rdi)
		mov    %edx,-0x4(%rdi)
		ret

		.balign 16
L(SSE13QB):	movdqa %xmm0,-0xbd(%rdi)
L(SSE13QA):	movdqa %xmm0,-0xad(%rdi)
L(SSE13Q9):	movdqa %xmm0,-0x9d(%rdi)
L(SSE13Q8):	movdqa %xmm0,-0x8d(%rdi)
L(SSE13Q7):	movdqa %xmm0,-0x7d(%rdi)
L(SSE13Q6):	movdqa %xmm0,-0x6d(%rdi)
L(SSE13Q5):	movdqa %xmm0,-0x5d(%rdi)
L(SSE13Q4):	movdqa %xmm0,-0x4d(%rdi)
L(SSE13Q3):	movdqa %xmm0,-0x3d(%rdi)
L(SSE13Q2):	movdqa %xmm0,-0x2d(%rdi)
L(SSE13Q1):	movdqa %xmm0,-0x1d(%rdi)
L(SSE13Q0):	mov    %rdx,-0xd(%rdi)
		mov    %edx,-0x5(%rdi)
		mov    %dl,-0x1(%rdi)
		ret

		.balign 16
L(SSE14QB):	movdqa %xmm0,-0xbe(%rdi)
L(SSE14QA):	movdqa %xmm0,-0xae(%rdi)
L(SSE14Q9):	movdqa %xmm0,-0x9e(%rdi)
L(SSE14Q8):	movdqa %xmm0,-0x8e(%rdi)
L(SSE14Q7):	movdqa %xmm0,-0x7e(%rdi)
L(SSE14Q6):	movdqa %xmm0,-0x6e(%rdi)
L(SSE14Q5):	movdqa %xmm0,-0x5e(%rdi)
L(SSE14Q4):	movdqa %xmm0,-0x4e(%rdi)
L(SSE14Q3):	movdqa %xmm0,-0x3e(%rdi)
L(SSE14Q2):	movdqa %xmm0,-0x2e(%rdi)
L(SSE14Q1):	movdqa %xmm0,-0x1e(%rdi)
L(SSE14Q0):	mov    %rdx,-0xe(%rdi)
		mov    %edx,-0x6(%rdi)
		mov    %dx,-0x2(%rdi)
		ret

		.balign 16
L(SSE15QB):	movdqa %xmm0,-0xbf(%rdi)
L(SSE15QA):	movdqa %xmm0,-0xaf(%rdi)
L(SSE15Q9):	movdqa %xmm0,-0x9f(%rdi)
L(SSE15Q8):	movdqa %xmm0,-0x8f(%rdi)
L(SSE15Q7):	movdqa %xmm0,-0x7f(%rdi)
L(SSE15Q6):	movdqa %xmm0,-0x6f(%rdi)
L(SSE15Q5):	movdqa %xmm0,-0x5f(%rdi)
L(SSE15Q4):	movdqa %xmm0,-0x4f(%rdi)
L(SSE15Q3):	movdqa %xmm0,-0x3f(%rdi)
L(SSE15Q2):	movdqa %xmm0,-0x2f(%rdi)
L(SSE15Q1):	movdqa %xmm0,-0x1f(%rdi)
L(SSE15Q0):	mov    %rdx,-0xf(%rdi)
		mov    %edx,-0x7(%rdi)
		mov    %dx,-0x3(%rdi)
		mov    %dl,-0x1(%rdi)
		ret

		.balign 16
L(byte32sse2_pre):                         
		mov    .largest_level_cache_size(%rip),%r9d
		cmp    %r9,%r8
		jg     L(sse2_nt_move)
		#jmp    L(byte32sse2)		# Fall thru...

		.balign 16               
L(byte32sse2):                             
		lea    -0x80(%r8),%r8		# 128
		cmp    $0x80,%r8
		movdqa %xmm0,(%rdi)
		movdqa %xmm0,0x10(%rdi)
		movdqa %xmm0,0x20(%rdi)
		movdqa %xmm0,0x30(%rdi)
		movdqa %xmm0,0x40(%rdi)
		movdqa %xmm0,0x50(%rdi)
		movdqa %xmm0,0x60(%rdi)
		movdqa %xmm0,0x70(%rdi)

		lea    0x80(%rdi),%rdi
		jge    L(byte32sse2)

		lea    L(SSExDx)(%rip),%r11
		add    %r8,%rdi
		movslq (%r11,%r8,4),%rcx
		lea    (%rcx,%r11,1),%r11
		jmpq   *%r11

		.balign	16               
L(sse2_nt_move):                           
		sub    $0x80,%r8		# 128
		movntdq %xmm0,(%rdi)
		movntdq %xmm0,0x10(%rdi)
		movntdq %xmm0,0x20(%rdi)
		movntdq %xmm0,0x30(%rdi)
		movntdq %xmm0,0x40(%rdi)
		movntdq %xmm0,0x50(%rdi)
		movntdq %xmm0,0x60(%rdi)
		movntdq %xmm0,0x70(%rdi)
		add    $0x80,%rdi
		cmp    $0x80,%r8
		jge    L(sse2_nt_move)

		sfence 
		lea    L(SSExDx)(%rip),%r11
		add    %r8,%rdi
		movslq (%r11,%r8,4),%rcx
		lea    (%rcx,%r11,1),%r11
		jmpq   *%r11

		/*
		 * Don't use SSE
		 */
		.balign 16
L(Loop8byte_pre):
		mov    .largest_level_cache_size(%rip),%r9d
		cmp    %r9,%r8
		jg     L(Loop8byte_nt_move)
		cmp    $0x800,%r8		# Use rep sstoq
		jge    L(use_rep)

		.balign 16               
L(Loop8byte):                             
		lea    -0x80(%r8),%r8		# 128
		mov    %rdx,(%rdi)
		mov    %rdx,0x8(%rdi)
		mov    %rdx,0x10(%rdi)
		mov    %rdx,0x18(%rdi)
		mov    %rdx,0x20(%rdi)
		mov    %rdx,0x28(%rdi)
		mov    %rdx,0x30(%rdi)
		mov    %rdx,0x38(%rdi)
		cmp    $0x80,%r8
		mov    %rdx,0x40(%rdi)
		mov    %rdx,0x48(%rdi)
		mov    %rdx,0x50(%rdi)
		mov    %rdx,0x58(%rdi)
		mov    %rdx,0x60(%rdi)
		mov    %rdx,0x68(%rdi)
		mov    %rdx,0x70(%rdi)
		mov    %rdx,0x78(%rdi)
		lea    0x80(%rdi),%rdi
		jge    L(Loop8byte)

1:
		lea    L(setPxQx)(%rip),%r11
		lea    (%rdi,%r8,1),%rdi

		movslq (%r11,%r8,4),%rcx
		lea    (%rcx,%r11,1),%r11
		jmpq   *%r11

		/*
		 * Use rep sstoq for sizes > 2K
		 */
		.balign 16
L(use_rep):
		movq   %r8,%rcx			# get size in bytes
		xchg   %rax,%rdx
		shrq   $3,%rcx
		rep
		  sstoq
		xchg   %rax,%rdx
		andq   $7,%r8			# remaining bytes
		jnz    1b
		ret

		.balign 16
L(Loop8byte_nt_move):
		lea    -0x40(%r8),%r8		# 64
		movnti %rdx,(%rdi)
		movnti %rdx,0x8(%rdi)
		movnti %rdx,0x10(%rdi)
		movnti %rdx,0x18(%rdi)
		cmp    $0x40,%r8
		movnti %rdx,0x20(%rdi)
		movnti %rdx,0x28(%rdi)
		movnti %rdx,0x30(%rdi)
		movnti %rdx,0x38(%rdi)
		lea    0x40(%rdi),%rdi
		jge    L(Loop8byte_nt_move)

		sfence
		lea    L(setPxQx)(%rip),%r11
		lea    (%rdi,%r8,1),%rdi

		movslq    (%r11,%r8,4),%rcx
		lea    (%rcx,%r11,1),%r11
		jmpq   *%r11

		.balign 16               
L(SSExDx):	.int       L(SSE0Q0) -L(SSExDx)
		.int       L(SSE1Q0) -L(SSExDx)
		.int       L(SSE2Q0) -L(SSExDx)
		.int       L(SSE3Q0) -L(SSExDx)
		.int       L(SSE4Q0) -L(SSExDx)
		.int       L(SSE5Q0) -L(SSExDx)
		.int       L(SSE6Q0) -L(SSExDx)
		.int       L(SSE7Q0) -L(SSExDx)

		.int       L(SSE8Q0) -L(SSExDx)
		.int       L(SSE9Q0) -L(SSExDx)
		.int       L(SSE10Q0)-L(SSExDx)
		.int       L(SSE11Q0)-L(SSExDx)
		.int       L(SSE12Q0)-L(SSExDx)
		.int       L(SSE13Q0)-L(SSExDx)
		.int       L(SSE14Q0)-L(SSExDx)
		.int       L(SSE15Q0)-L(SSExDx) 

		.int       L(SSE0Q1) -L(SSExDx)
		.int       L(SSE1Q1) -L(SSExDx)
		.int       L(SSE2Q1) -L(SSExDx)
		.int       L(SSE3Q1) -L(SSExDx)
		.int       L(SSE4Q1) -L(SSExDx)
		.int       L(SSE5Q1) -L(SSExDx)
		.int       L(SSE6Q1) -L(SSExDx)
		.int       L(SSE7Q1) -L(SSExDx)

		.int       L(SSE8Q1) -L(SSExDx)
		.int       L(SSE9Q1) -L(SSExDx)
		.int       L(SSE10Q1)-L(SSExDx)
		.int       L(SSE11Q1)-L(SSExDx)
		.int       L(SSE12Q1)-L(SSExDx)
		.int       L(SSE13Q1)-L(SSExDx)
		.int       L(SSE14Q1)-L(SSExDx)
		.int       L(SSE15Q1)-L(SSExDx) 

		.int       L(SSE0Q2) -L(SSExDx)
		.int       L(SSE1Q2) -L(SSExDx)
		.int       L(SSE2Q2) -L(SSExDx)
		.int       L(SSE3Q2) -L(SSExDx)
		.int       L(SSE4Q2) -L(SSExDx)
		.int       L(SSE5Q2) -L(SSExDx)
		.int       L(SSE6Q2) -L(SSExDx)
		.int       L(SSE7Q2) -L(SSExDx)

		.int       L(SSE8Q2) -L(SSExDx)
		.int       L(SSE9Q2) -L(SSExDx)
		.int       L(SSE10Q2)-L(SSExDx)
		.int       L(SSE11Q2)-L(SSExDx)
		.int       L(SSE12Q2)-L(SSExDx)
		.int       L(SSE13Q2)-L(SSExDx)
		.int       L(SSE14Q2)-L(SSExDx)
		.int       L(SSE15Q2)-L(SSExDx) 

		.int       L(SSE0Q3) -L(SSExDx)
		.int       L(SSE1Q3) -L(SSExDx)
		.int       L(SSE2Q3) -L(SSExDx)
		.int       L(SSE3Q3) -L(SSExDx)
		.int       L(SSE4Q3) -L(SSExDx)
		.int       L(SSE5Q3) -L(SSExDx)
		.int       L(SSE6Q3) -L(SSExDx)
		.int       L(SSE7Q3) -L(SSExDx)

		.int       L(SSE8Q3) -L(SSExDx)
		.int       L(SSE9Q3) -L(SSExDx)
		.int       L(SSE10Q3)-L(SSExDx)
		.int       L(SSE11Q3)-L(SSExDx)
		.int       L(SSE12Q3)-L(SSExDx)
		.int       L(SSE13Q3)-L(SSExDx)
		.int       L(SSE14Q3)-L(SSExDx)
		.int       L(SSE15Q3)-L(SSExDx) 

		.int       L(SSE0Q4) -L(SSExDx)
		.int       L(SSE1Q4) -L(SSExDx)
		.int       L(SSE2Q4) -L(SSExDx)
		.int       L(SSE3Q4) -L(SSExDx)
		.int       L(SSE4Q4) -L(SSExDx)
		.int       L(SSE5Q4) -L(SSExDx)
		.int       L(SSE6Q4) -L(SSExDx)
		.int       L(SSE7Q4) -L(SSExDx)

		.int       L(SSE8Q4) -L(SSExDx)
		.int       L(SSE9Q4) -L(SSExDx)
		.int       L(SSE10Q4)-L(SSExDx)
		.int       L(SSE11Q4)-L(SSExDx)
		.int       L(SSE12Q4)-L(SSExDx)
		.int       L(SSE13Q4)-L(SSExDx)
		.int       L(SSE14Q4)-L(SSExDx)
		.int       L(SSE15Q4)-L(SSExDx) 

		.int       L(SSE0Q5) -L(SSExDx)
		.int       L(SSE1Q5) -L(SSExDx)
		.int       L(SSE2Q5) -L(SSExDx)
		.int       L(SSE3Q5) -L(SSExDx)
		.int       L(SSE4Q5) -L(SSExDx)
		.int       L(SSE5Q5) -L(SSExDx)
		.int       L(SSE6Q5) -L(SSExDx)
		.int       L(SSE7Q5) -L(SSExDx)

		.int       L(SSE8Q5) -L(SSExDx)
		.int       L(SSE9Q5) -L(SSExDx)
		.int       L(SSE10Q5)-L(SSExDx)
		.int       L(SSE11Q5)-L(SSExDx)
		.int       L(SSE12Q5)-L(SSExDx)
		.int       L(SSE13Q5)-L(SSExDx)
		.int       L(SSE14Q5)-L(SSExDx)
		.int       L(SSE15Q5)-L(SSExDx) 

		.int       L(SSE0Q6) -L(SSExDx)
		.int       L(SSE1Q6) -L(SSExDx)
		.int       L(SSE2Q6) -L(SSExDx)
		.int       L(SSE3Q6) -L(SSExDx)
		.int       L(SSE4Q6) -L(SSExDx)
		.int       L(SSE5Q6) -L(SSExDx)
		.int       L(SSE6Q6) -L(SSExDx)
		.int       L(SSE7Q6) -L(SSExDx)

		.int       L(SSE8Q6) -L(SSExDx)
		.int       L(SSE9Q6) -L(SSExDx)
		.int       L(SSE10Q6)-L(SSExDx)
		.int       L(SSE11Q6)-L(SSExDx)
		.int       L(SSE12Q6)-L(SSExDx)
		.int       L(SSE13Q6)-L(SSExDx)
		.int       L(SSE14Q6)-L(SSExDx)
		.int       L(SSE15Q6)-L(SSExDx) 

		.int       L(SSE0Q7) -L(SSExDx)
		.int       L(SSE1Q7) -L(SSExDx)
		.int       L(SSE2Q7) -L(SSExDx)
		.int       L(SSE3Q7) -L(SSExDx)
		.int       L(SSE4Q7) -L(SSExDx)
		.int       L(SSE5Q7) -L(SSExDx)
		.int       L(SSE6Q7) -L(SSExDx)
		.int       L(SSE7Q7) -L(SSExDx)

		.int       L(SSE8Q7) -L(SSExDx)
		.int       L(SSE9Q7) -L(SSExDx)
		.int       L(SSE10Q7)-L(SSExDx)
		.int       L(SSE11Q7)-L(SSExDx)
		.int       L(SSE12Q7)-L(SSExDx)
		.int       L(SSE13Q7)-L(SSExDx)
		.int       L(SSE14Q7)-L(SSExDx)
		.int       L(SSE15Q7)-L(SSExDx) 

		.int       L(SSE0Q8) -L(SSExDx)
		.int       L(SSE1Q8) -L(SSExDx)
		.int       L(SSE2Q8) -L(SSExDx)
		.int       L(SSE3Q8) -L(SSExDx)
		.int       L(SSE4Q8) -L(SSExDx)
		.int       L(SSE5Q8) -L(SSExDx)
		.int       L(SSE6Q8) -L(SSExDx)
		.int       L(SSE7Q8) -L(SSExDx)

		.int       L(SSE8Q8) -L(SSExDx)
		.int       L(SSE9Q8) -L(SSExDx)
		.int       L(SSE10Q8)-L(SSExDx)
		.int       L(SSE11Q8)-L(SSExDx)
		.int       L(SSE12Q8)-L(SSExDx)
		.int       L(SSE13Q8)-L(SSExDx)
		.int       L(SSE14Q8)-L(SSExDx)
		.int       L(SSE15Q8)-L(SSExDx) 

		.int       L(SSE0Q9) -L(SSExDx)
		.int       L(SSE1Q9) -L(SSExDx)
		.int       L(SSE2Q9) -L(SSExDx)
		.int       L(SSE3Q9) -L(SSExDx)
		.int       L(SSE4Q9) -L(SSExDx)
		.int       L(SSE5Q9) -L(SSExDx)
		.int       L(SSE6Q9) -L(SSExDx)
		.int       L(SSE7Q9) -L(SSExDx)

		.int       L(SSE8Q9) -L(SSExDx)
		.int       L(SSE9Q9) -L(SSExDx)
		.int       L(SSE10Q9)-L(SSExDx)
		.int       L(SSE11Q9)-L(SSExDx)
		.int       L(SSE12Q9)-L(SSExDx)
		.int       L(SSE13Q9)-L(SSExDx)
		.int       L(SSE14Q9)-L(SSExDx)
		.int       L(SSE15Q9)-L(SSExDx) 

		.int       L(SSE0QA) -L(SSExDx)
		.int       L(SSE1QA) -L(SSExDx)
		.int       L(SSE2QA) -L(SSExDx)
		.int       L(SSE3QA) -L(SSExDx)
		.int       L(SSE4QA) -L(SSExDx)
		.int       L(SSE5QA) -L(SSExDx)
		.int       L(SSE6QA) -L(SSExDx)
		.int       L(SSE7QA) -L(SSExDx)

		.int       L(SSE8QA) -L(SSExDx)
		.int       L(SSE9QA) -L(SSExDx)
		.int       L(SSE10QA)-L(SSExDx)
		.int       L(SSE11QA)-L(SSExDx)
		.int       L(SSE12QA)-L(SSExDx)
		.int       L(SSE13QA)-L(SSExDx)
		.int       L(SSE14QA)-L(SSExDx)
		.int       L(SSE15QA)-L(SSExDx) 

		.int       L(SSE0QB) -L(SSExDx)
		.int       L(SSE1QB) -L(SSExDx)
		.int       L(SSE2QB) -L(SSExDx)
		.int       L(SSE3QB) -L(SSExDx)
		.int       L(SSE4QB) -L(SSExDx)
		.int       L(SSE5QB) -L(SSExDx)
		.int       L(SSE6QB) -L(SSExDx)
		.int       L(SSE7QB) -L(SSExDx)

		.int       L(SSE8QB) -L(SSExDx)
		.int       L(SSE9QB) -L(SSExDx)
		.int       L(SSE10QB)-L(SSExDx)
		.int       L(SSE11QB)-L(SSExDx)
		.int       L(SSE12QB)-L(SSExDx)
		.int       L(SSE13QB)-L(SSExDx)
		.int       L(SSE14QB)-L(SSExDx)
		.int       L(SSE15QB)-L(SSExDx) 

		SET_SIZE(memset)
