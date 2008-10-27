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

	.file	"strcpy.s"

#include "SYS.h"
#include "cache.h"

#define LABEL(s) .strcpy/**/s

#ifdef USE_AS_STRNCPY
	ENTRY(strncpy)
#else
	ENTRY(strcpy)                        /* (char *, const char *) */
#endif

#ifdef USE_AS_STRNCPY
	test	%rdx, %rdx		/* (char *, const char *, size_t) */
	mov	%rdx, %r11
	jz	LABEL(exitn)		/* early exit */
#endif

        xor     %edx, %edx

LABEL(aligntry):
        mov     %rsi, %r8		/* align by source */
        and     $7, %r8
	jz	LABEL(alignafter)

LABEL(align):				/* 8-byte align */
        sub     $8, %r8

	.p2align 4

LABEL(alignloop):
#ifdef USE_AS_STRNCPY
	dec	%r11
	jl	LABEL(exitn)
#endif

        mov     (%rsi, %rdx), %al       /* check if same character */
        test    %al, %al                /* check if character a NUL */
        mov     %al, (%rdi, %rdx)
        jz      LABEL(exit)

        inc     %edx
        inc     %r8
        jnz     LABEL(alignloop)

#ifdef USE_AS_STRNCPY
	test	%r11, %r11		/* must check remaining size */
	jz	LABEL(exitn)		/* If we've already done, exit */
#endif

	.p2align 4

LABEL(alignafter):

LABEL(8try):
        mov     $0xfefefefefefefeff, %rcx

LABEL(8):                               /* 8-byte */
        mov     (%rsi, %rdx), %rax

LABEL(8loop):
#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

LABEL(8after):

LABEL(64try):
        mov     _sref_(.amd64cache1half), %r9

LABEL(64):				/* 64-byte */

        .p2align 4

LABEL(64loop):
#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        cmp     %r9, %rdx

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        lea     8 (%rdx), %rdx

        jbe     LABEL(64loop)

LABEL(64after):

LABEL(pretry):
        mov     _sref_(.amd64cache2half), %r9

LABEL(pre):                              /* 64-byte prefetch */

        .p2align 4

LABEL(preloop):
#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        mov     %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %edx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(tail)

        cmp     %r9, %rdx

        mov     %rax, (%rdi, %rdx)
        prefetchnta 512 + 8 (%rdi, %rdx)	/* 3DNow: use prefetchw */
        mov     8 (%rsi, %rdx), %rax
        prefetchnta 512 + 8 (%rsi, %rdx)	/* 3DNow: use prefetch */
        lea     8 (%rdx), %rdx

        jb	LABEL(preloop)

        .p2align 4

LABEL(preafter):

LABEL(NTtry):
	mfence

LABEL(NT):				/* 64-byte NT */

        .p2align 4

LABEL(NTloop):
#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(NTtail)

        movnti  %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %rdx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(NTtail)

        movnti  %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %rdx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(NTtail)

        movnti  %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %rdx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(NTtail)

        movnti  %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %rdx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(NTtail)

        movnti  %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %rdx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(NTtail)

        movnti  %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %rdx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(NTtail)

        movnti  %rax, (%rdi, %rdx)
        mov     8 (%rsi, %rdx), %rax
        add     $8, %rdx

#ifdef USE_AS_STRNCPY
	sub	$8, %r11
	jle	LABEL(tail)
#endif

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %r10, %r10

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %r10, %r8
        jnz     LABEL(NTtail)

        movnti  %rax, (%rdi, %rdx)
	mov     8 (%rsi, %rdx), %rax
	prefetchnta 768 + 8 (%rsi, %rdx)
        add     $8, %rdx

        jmp     LABEL(NTloop)

        .p2align 4

LABEL(NTtail):
	mfence

        .p2align 4

LABEL(NTafter):

LABEL(tailtry):

LABEL(tail):                             /* 1-byte tail */
#ifdef USE_AS_STRNCPY
	add	$8, %r11
#endif

        .p2align 4

LABEL(tailloop):
#ifdef USE_AS_STRNCPY
	dec	%r11
	jl	LABEL(exitn)
#endif

        test    %al, %al
        mov     %al, (%rdi, %rdx)
        jz      LABEL(exit)

        inc     %rdx

#ifdef USE_AS_STRNCPY
	dec	%r11
	jl	LABEL(exitn)

	mov	%ah, %al
#endif

        test    %ah, %ah
        mov     %ah, (%rdi, %rdx)
        jz      LABEL(exit)

        inc     %rdx

#ifdef USE_AS_STRNCPY
	dec	%r11
	jl	LABEL(exitn)
#endif

        shr     $16, %rax

        test    %al, %al
        mov     %al, (%rdi, %rdx)
        jz      LABEL(exit)

        inc     %rdx

#ifdef USE_AS_STRNCPY
	dec	%r11
	jl	LABEL(exitn)

	mov	%ah, %al
#endif

        test    %ah, %ah
        mov     %ah, (%rdi, %rdx)
        jz      LABEL(exit)

        shr     $16, %rax
        inc     %rdx

        jmp     LABEL(tailloop)

        .p2align 4

LABEL(tailafter):

LABEL(exit):
#ifdef USE_AS_STRNCPY
	test	%r11, %r11
	mov	%r11, %rcx

#ifdef USE_AS_STPCPY
        lea     (%rdi, %rdx), %r8
#else
        mov     %rdi, %r8
#endif

	jz	2f

	xor	%eax, %eax		/* bzero () would do too, but usually there are only a handfull of bytes left */
	shr	$3, %rcx
        lea     1 (%rdi, %rdx), %rdi
	jz	1f

	rep	stosq

1:
	mov	%r11d, %ecx
	and	$7, %ecx
	jz	2f

        .p2align 4,, 3

3:
	dec	%ecx
	mov	%al, (%rdi, %rcx)
	jnz	3b

        .p2align 4,, 3

2:
	mov	%r8, %rax
        ret

#endif

        .p2align 4

LABEL(exitn):
#ifdef USE_AS_STPCPY
        lea     (%rdi, %rdx), %rax
#else
        mov     %rdi, %rax
#endif

        ret

#ifdef USE_AS_STRNCPY
	SET_SIZE(strncpy)
#else
	SET_SIZE(strcpy)                        /* (char *, const char *) */
#endif
