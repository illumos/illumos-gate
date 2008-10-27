/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2002 Advanced Micro Devices, Inc.
 * 
 * All rights reserved.
 * 
 * Redistribution and  use in source and binary  forms, with or
 * without  modification,  are   permitted  provided  that  the
 * following conditions are met:
 * 
 * + Redistributions  of source  code  must  retain  the  above
 *   copyright  notice,   this  list  of   conditions  and  the
 *   following disclaimer.
 * 
 * + Redistributions  in binary  form must reproduce  the above
 *   copyright  notice,   this  list  of   conditions  and  the
 *   following  disclaimer in  the  documentation and/or  other
 *   materials provided with the distribution.
 * 
 * + Neither the  name of Advanced Micro Devices,  Inc. nor the
 *   names  of  its contributors  may  be  used  to endorse  or
 *   promote  products  derived   from  this  software  without
 *   specific prior written permission.
 * 
 * THIS  SOFTWARE  IS PROVIDED  BY  THE  COPYRIGHT HOLDERS  AND
 * CONTRIBUTORS AS IS AND  ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING,  BUT NOT  LIMITED TO,  THE IMPLIED  WARRANTIES OF
 * MERCHANTABILITY  AND FITNESS  FOR A  PARTICULAR  PURPOSE ARE
 * DISCLAIMED.  IN  NO  EVENT  SHALL  ADVANCED  MICRO  DEVICES,
 * INC.  OR CONTRIBUTORS  BE LIABLE  FOR ANY  DIRECT, INDIRECT,
 * INCIDENTAL,  SPECIAL,  EXEMPLARY,  OR CONSEQUENTIAL  DAMAGES
 * (INCLUDING,  BUT NOT LIMITED  TO, PROCUREMENT  OF SUBSTITUTE
 * GOODS  OR  SERVICES;  LOSS  OF  USE, DATA,  OR  PROFITS;  OR
 * BUSINESS INTERRUPTION)  HOWEVER CAUSED AND ON  ANY THEORY OF
 * LIABILITY,  WHETHER IN CONTRACT,  STRICT LIABILITY,  OR TORT
 * (INCLUDING NEGLIGENCE  OR OTHERWISE) ARISING IN  ANY WAY OUT
 * OF THE  USE  OF  THIS  SOFTWARE, EVEN  IF  ADVISED  OF  THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * It is  licensee's responsibility  to comply with  any export
 * regulations applicable in licensee's jurisdiction.
 */

	.file	"strcmp.s"

#include "SYS.h"
#include "cache.h"

#define LABEL(s) .strcmp/**/s

#ifdef USE_AS_STRNCMP
	ENTRY(strncmp)
#else
	ENTRY(strcmp)			/* (const char *, const char *) */
#endif
        xor     %ecx, %ecx

#ifdef USE_AS_STRNCMP
	test	%rdx, %rdx		/* (const char *, const char *, size_t) */
        mov	%r14, -8 (%rsp)
	mov	%rdx, %r14
	mov	%edx, %eax
	jz	LABEL(exitz)		/* early exit */
#endif

LABEL(aligntry):
        mov     %rsi, %r8		/* align by "source" */
        and     $8 - 1, %r8		/* between 0 and 8 characters compared */
	jz	LABEL(alignafter)

LABEL(align):
        sub     $8, %r8

        .p2align 4

LABEL(alignloop):
        mov     (%rsi, %rcx), %al
        mov	(%rdi, %rcx), %dl

#ifdef USE_AS_STRNCMP
	dec	%r14
	jl	LABEL(exitafter)
#endif

        cmp     %dl, %al		/* check if same character */
        jne     LABEL(exitafter)
        test    %al, %al		/* check if character a NUL */
        jz      LABEL(exitafter)

        inc     %ecx

        inc     %r8
        jnz     LABEL(alignloop)

#ifdef USE_AS_STRNCMP
        test	%r14, %r14
        jz	LABEL(exitafter)
#endif

        .p2align 4

LABEL(alignafter):

        mov	%r15, -32 (%rsp)
        mov	%rbp, -24 (%rsp)
        mov	%rbx, -16 (%rsp)

LABEL(pagealigntry):			/* page align by "destination" */
        lea	(%rdi, %rcx), %ebp
	mov	$AMD64PAGESIZE, %r15d
        and     $AMD64PAGEMASK, %ebp
        sub	%r15d, %ebp
	/*
	 * When we go to 64gobble, %ebp was adjusted at the top of 64loop.
	 * When we go to 64nibble(crossing page boundary), we'll compare
	 * 128 byte since we'll fall through to 64gobble. Therefore, %ebp
	 * needs to be re-adjusted(add 64) when we fall into 64nibble.
	 * It can be done by adjusting %r15 since %r15 is only used to
	 * rewind %ebp when crossing page boundary.
	 */
	sub	$64, %r15d

LABEL(64):                              /* 64-byte */
	mov     $0xfefefefefefefeff, %rbx /* magic number */

        .p2align 4

LABEL(64loop):
	add	$64, %ebp		/* check if "destination" crosses a page unevenly */
	jle	LABEL(64gobble)

        sub	%r15d, %ebp
        lea	64 (%rcx), %r8

        .p2align 4

LABEL(64nibble):
        mov     (%rsi, %rcx), %al
        mov	(%rdi, %rcx), %dl

#ifdef USE_AS_STRNCMP
	dec	%r14
	jle	LABEL(exit)
#endif

        cmp     %dl, %al		/* check if same character */
        jne     LABEL(exit)
        test    %al, %al		/* check if character a NUL */
        jz      LABEL(exit)

        inc	%ecx

        cmp	%ecx, %r8d
        ja	LABEL(64nibble)

        .p2align 4

LABEL(64gobble):
        mov     (%rsi, %rcx), %rax
        mov     (%rdi, %rcx), %rdx

#ifdef USE_AS_STRNCMP
	sub	$8, %r14
	jle	LABEL(tail)
#endif

        mov     %rbx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        mov     %rbx, %r9
        add     %rdx, %r9
        sbb     %r11, %r11

        xor     %rax, %r8
        or      %rbx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        xor     %rdx, %r9
        or      %rbx, %r9
        sub     %r11, %r9
        jnz     LABEL(tail)

        cmp     %rdx, %rax
        jne     LABEL(tail)

        mov     8 (%rsi, %rcx), %rax
        mov     8 (%rdi, %rcx), %rdx
        add     $8, %ecx

#ifdef USE_AS_STRNCMP
	sub	$8, %r14
	jle	LABEL(tail)
#endif

        mov     %rbx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        mov     %rbx, %r9
        add     %rdx, %r9
        sbb     %r11, %r11

        xor     %rax, %r8
        or      %rbx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        xor     %rdx, %r9
        or      %rbx, %r9
        sub     %r11, %r9
        jnz     LABEL(tail)

        cmp     %rdx, %rax
        jne     LABEL(tail)

        mov     8 (%rsi, %rcx), %rax
        mov     8 (%rdi, %rcx), %rdx
        add     $8, %ecx

#ifdef USE_AS_STRNCMP
	sub	$8, %r14
	jle	LABEL(tail)
#endif

        mov     %rbx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        mov     %rbx, %r9
        add     %rdx, %r9
        sbb     %r11, %r11

        xor     %rax, %r8
        or      %rbx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        xor     %rdx, %r9
        or      %rbx, %r9
        sub     %r11, %r9
        jnz     LABEL(tail)

        cmp     %rdx, %rax
        jne     LABEL(tail)

        mov     8 (%rsi, %rcx), %rax
        mov     8 (%rdi, %rcx), %rdx
        add     $8, %ecx

#ifdef USE_AS_STRNCMP
	sub	$8, %r14
	jle	LABEL(tail)
#endif

        mov     %rbx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        mov     %rbx, %r9
        add     %rdx, %r9
        sbb     %r11, %r11

        xor     %rax, %r8
        or      %rbx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        xor     %rdx, %r9
        or      %rbx, %r9
        sub     %r11, %r9
        jnz     LABEL(tail)

        cmp     %rdx, %rax
        jne     LABEL(tail)

        mov     8 (%rsi, %rcx), %rax
        mov     8 (%rdi, %rcx), %rdx
        add     $8, %ecx

#ifdef USE_AS_STRNCMP
	sub	$8, %r14
	jle	LABEL(tail)
#endif

        mov     %rbx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        mov     %rbx, %r9
        add     %rdx, %r9
        sbb     %r11, %r11

        xor     %rax, %r8
        or      %rbx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        xor     %rdx, %r9
        or      %rbx, %r9
        sub     %r11, %r9
        jnz     LABEL(tail)

        cmp     %rdx, %rax
        jne     LABEL(tail)

        mov     8 (%rsi, %rcx), %rax
        mov     8 (%rdi, %rcx), %rdx
        add     $8, %ecx

#ifdef USE_AS_STRNCMP
	sub	$8, %r14
	jle	LABEL(tail)
#endif

        mov     %rbx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        mov     %rbx, %r9
        add     %rdx, %r9
        sbb     %r11, %r11

        xor     %rax, %r8
        or      %rbx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        xor     %rdx, %r9
        or      %rbx, %r9
        sub     %r11, %r9
        jnz     LABEL(tail)

        cmp     %rdx, %rax
        jne     LABEL(tail)

        mov     8 (%rsi, %rcx), %rax
        mov     8 (%rdi, %rcx), %rdx
        add     $8, %ecx

#ifdef USE_AS_STRNCMP
	sub	$8, %r14
	jle	LABEL(tail)
#endif

        mov     %rbx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        mov     %rbx, %r9
        add     %rdx, %r9
        sbb     %r11, %r11

        xor     %rax, %r8
        or      %rbx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        xor     %rdx, %r9
        or      %rbx, %r9
        sub     %r11, %r9
        jnz     LABEL(tail)

        cmp     %rdx, %rax
        jne     LABEL(tail)

        mov     8 (%rsi, %rcx), %rax
        mov     8 (%rdi, %rcx), %rdx
        add     $8, %ecx

#ifdef USE_AS_STRNCMP
	sub	$8, %r14
	jle	LABEL(tail)
#endif

        mov     %rbx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        mov     %rbx, %r9
        add     %rdx, %r9
        sbb     %r11, %r11

        xor     %rax, %r8
        or      %rbx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        xor     %rdx, %r9
        or      %rbx, %r9
        sub     %r11, %r9
        jnz     LABEL(tail)

        cmp     %rdx, %rax
        jne     LABEL(tail)

        add	$8, %ecx

        jmp	LABEL(64loop)

LABEL(64after):

LABEL(tailtry):

LABEL(tail):				/* byte tail */
#ifdef USE_AS_STRNCMP
	add	$7, %r14
#endif

        cmp     %dl, %al		/* check if same character */
        jne     LABEL(exit)
        test    %al, %al		/* check if character a NUL */
        jz      LABEL(exit)

        shr	$8, %rax
        shr	$8, %rdx

#ifdef USE_AS_STRNCMP
	dec	%r14
	jl	LABEL(exit)
#endif

        cmp     %dl, %al
        jne     LABEL(exit)
        test    %al, %al
        jz      LABEL(exit)

        shr	$8, %rax
        shr	$8, %rdx

#ifdef USE_AS_STRNCMP
	dec	%r14
	jl	LABEL(exit)
#endif

        cmp     %dl, %al
        jne     LABEL(exit)
        test    %al, %al
        jz      LABEL(exit)

        shr	$8, %rax
        shr	$8, %rdx

#ifdef USE_AS_STRNCMP
	dec	%r14
	jl	LABEL(exit)
#endif

        cmp     %dl, %al
        jne     LABEL(exit)
        test    %al, %al
        jz      LABEL(exit)

        shr	$8, %rax
        shr	$8, %rdx

#ifdef USE_AS_STRNCMP
	dec	%r14
	jl	LABEL(exit)
#endif

        cmp     %dl, %al
        jne     LABEL(exit)
        test    %al, %al
        jz      LABEL(exit)

        shr	$8, %eax
        shr	$8, %edx

#ifdef USE_AS_STRNCMP
	dec	%r14
	jl	LABEL(exit)
#endif

        cmp     %dl, %al
        jne     LABEL(exit)
        test    %al, %al
        jz      LABEL(exit)

        shr	$8, %eax
        shr	$8, %edx

#ifdef USE_AS_STRNCMP
	dec	%r14
	jl	LABEL(exit)
#endif

        cmp     %dl, %al
        jne     LABEL(exit)
        test    %al, %al
        jz      LABEL(exit)

        shr	$8, %eax
        shr	$8, %edx

#ifdef USE_AS_STRNCMP
	dec	%r14
	jl	LABEL(exit)
#endif

        cmp     %dl, %al
        jne     LABEL(exit)

        .p2align 4,, 15

LABEL(tailafter):

LABEL(exit):
	mov	-32 (%rsp), %r15
	mov	-24 (%rsp), %rbp
        mov	-16 (%rsp), %rbx

        .p2align 4,, 3

LABEL(exitafter):
#ifdef USE_AS_STRNCMP
	test	%r14, %r14
	cmovl	%edx, %eax
#endif

	movzx	%al, %eax
	movzx	%dl, %edx
	sub	%eax, %edx
	xchg	%edx, %eax

#ifdef USE_AS_STRNCMP
LABEL(exitz):
	mov	-8 (%rsp), %r14
#endif
        ret

#ifdef USE_AS_STRNCMP
	SET_SIZE(strncmp)
#else
	SET_SIZE(strcmp)		/* (const char *, const char *) */
#endif
