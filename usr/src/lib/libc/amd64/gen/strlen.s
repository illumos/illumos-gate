/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
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

	.file	"strlen.s"

#include "SYS.h"
#include "cache.h"

#define LABEL(s) .strlen/**/s

	ENTRY(strlen)                /* (const char *s) */

        mov     %rdi, %rsi
        neg     %rdi

LABEL(aligntry):
        mov     %rsi , %r8
        and     $7, %r8d
	jz	LABEL(alignafter)

LABEL(align):                            /* 8-byte align */
        sub     $8, %r8

        .p2align 4

LABEL(alignloop):
        cmpb    $0, (%rsi)
        je      LABEL(exit)

        inc     %rsi
        inc     %r8
        jnz     LABEL(alignloop)

        .p2align 4

LABEL(alignafter):

LABEL(56try):

LABEL(56):                               /* 56-byte */
        mov     (%rsi), %rax
        mov     $0xfefefefefefefeff, %rcx

LABEL(56loop):
        mov     %rcx, %r8
        add     %rax, %r8
        jnc     LABEL(tail)

        xor     %rax, %r8
        or      %rcx, %r8
        inc     %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        lea     8 (%rsi), %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        jnc     LABEL(tail)

        xor     %rax, %r8
        or      %rcx, %r8
        inc     %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        lea     8 (%rsi), %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        jnc     LABEL(tail)

        xor     %rax, %r8
        or      %rcx, %r8
        inc     %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        lea     8 (%rsi), %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        jnc     LABEL(tail)

        xor     %rax, %r8
        or      %rcx, %r8
        inc     %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        lea     8 (%rsi), %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        jnc     LABEL(tail)

        xor     %rax, %r8
        or      %rcx, %r8
        inc     %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        lea     8 (%rsi), %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        jnc     LABEL(tail)

        xor     %rax, %r8
        or      %rcx, %r8
        inc     %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        lea     8 (%rsi), %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        jnc     LABEL(tail)

        xor     %rax, %r8
        or      %rcx, %r8
        inc     %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        lea     8 (%rsi), %rsi

LABEL(56after):

LABEL(32):                               /* 32-byte */
        mov     _sref_(.amd64cache1), %r9

        .p2align 4

LABEL(32loop):
        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %rdx, %rdx

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %rdx, %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        add     $8, %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %rdx, %rdx

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %rdx, %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        add     $8, %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %rdx, %rdx

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %rdx, %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        add     $8, %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %rdx, %rdx

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %rdx, %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        add     $8, %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %rdx, %rdx

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %rdx, %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        add     $8, %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %rdx, %rdx

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %rdx, %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        add     $8, %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %rdx, %rdx

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %rdx, %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        add     $8, %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %rdx, %rdx

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %rdx, %r8
        jnz     LABEL(tail)

        sub     $32, %r9

        mov     8 (%rsi), %rax
        lea     8 (%rsi), %rsi

        jbe     LABEL(32loop)

LABEL(32after):

LABEL(pretry):

LABEL(pre):                              /* 64-byte prefetch */

        .p2align 4

LABEL(preloop):
        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %rdx, %rdx

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %rdx, %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        add     $8, %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %rdx, %rdx

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %rdx, %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        add     $8, %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %rdx, %rdx

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %rdx, %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        add     $8, %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %rdx, %rdx

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %rdx, %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        add     $8, %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %rdx, %rdx

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %rdx, %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        add     $8, %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %rdx, %rdx

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %rdx, %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        add     $8, %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %rdx, %rdx

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %rdx, %r8
        jnz     LABEL(tail)

        mov     8 (%rsi), %rax
        add     $8, %rsi

        mov     %rcx, %r8
        add     %rax, %r8
        sbb     %rdx, %rdx

        xor     %rax, %r8
        or      %rcx, %r8
        sub     %rdx, %r8
        jnz     LABEL(tail)

        prefetchnta 512 (%rsi)	/* 3DNow: use prefetch */

        mov     8 (%rsi), %rax
        add     $8, %rsi

        jmp     LABEL(preloop)

        .p2align 4

LABEL(preafter):

LABEL(tailtry):

LABEL(tail):                             /* 4-byte tail */

LABEL(tailloop):
        test    %al, %al
        jz      LABEL(exit)

        inc     %rsi

        test    %ah, %ah
        jz      LABEL(exit)

        inc     %rsi

        test    $0x00ff0000, %eax
        jz      LABEL(exit)

        inc     %rsi

        test    $0xff000000, %eax
        jz      LABEL(exit)

        inc     %rsi

        shr     $32, %rax
        jmp     LABEL(tailloop)

LABEL(tailafter):

        .p2align 4

LABEL(exit):
        lea     (%rdi, %rsi), %rax
        ret

	SET_SIZE(strlen)
