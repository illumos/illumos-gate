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

	.file	"memcmp.s"

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(memcmp,function)

#include "SYS.h"
#include "cache.h"

#define LABEL(s) .memcmp/**/s

	ENTRY(memcmp)                 /* (const void *, const void*, size_t) */

LABEL(try1):
        cmp     $8, %rdx
        jae     LABEL(1after)

LABEL(1):                                /* 1-byte */
        test    %rdx, %rdx
        mov     $0, %eax
        jz      LABEL(exit)

LABEL(1loop):
        movzbl  (%rdi), %eax
        movzbl  (%rsi), %ecx
        sub     %ecx, %eax
        jnz     LABEL(exit)

        dec     %rdx

        lea     1 (%rdi), %rdi
        lea     1 (%rsi), %rsi

        jnz     LABEL(1loop)

LABEL(exit):
        rep
        ret

        .p2align 4

LABEL(1after):

LABEL(8try):
        cmp     $32, %rdx
        jae     LABEL(8after)

LABEL(8):                        /* 8-byte */
        mov     %edx, %ecx
        shr     $3, %ecx
        jz      LABEL(1)

        .p2align 4

LABEL(8loop):
        mov     (%rsi), %rax
        cmp     (%rdi), %rax
        jne     LABEL(1)

        sub     $8, %rdx
        dec     %ecx

        lea     8 (%rsi), %rsi
        lea     8 (%rdi), %rdi

        jnz     LABEL(8loop)

LABEL(8skip):
        and     $7, %edx
        jnz     LABEL(1)

        xor     %eax, %eax
        ret

        .p2align 4

LABEL(8after):

LABEL(32try):
        cmp     $2048, %rdx
        ja      LABEL(32after)

LABEL(32):                               /* 32-byte */
        mov     %edx, %ecx
        shr     $5, %ecx
        jz      LABEL(8)

        .p2align 4

LABEL(32loop):
        mov        (%rsi), %rax
        mov      8 (%rsi),  %r8
        mov     16 (%rsi),  %r9
        mov     24 (%rsi), %r10
        sub        (%rdi), %rax
        sub      8 (%rdi),  %r8
        sub     16 (%rdi),  %r9
        sub     24 (%rdi), %r10

        or      %rax,  %r8
        or       %r9, %r10
        or       %r8, %r10
        jnz     LABEL(8)

        sub     $32, %rdx
        dec     %ecx

        lea     32 (%rsi), %rsi
        lea     32 (%rdi), %rdi

        jnz     LABEL(32loop)

LABEL(32skip):
        and     $31, %edx
        jnz     LABEL(8)

        xor     %eax, %eax
        ret

        .p2align 4

LABEL(32after):

	prefetchnta _sref_(.amd64cache1half)	/* 3DNow: use prefetch */

LABEL(srctry):
        mov     %esi, %r8d      /* align by source */

        and     $7, %r8d
        jz      LABEL(srcafter)  /* not unaligned */

LABEL(src):                      /* align */
        lea     -8 (%r8, %rdx), %rdx
        sub     $8, %r8d


LABEL(srcloop):
        movzbl  (%rdi), %eax
        movzbl  (%rsi), %ecx
        sub     %ecx, %eax
        jnz     LABEL(exit)

        inc     %r8d

        lea     1 (%rdi), %rdi
        lea     1 (%rsi), %rsi

        jnz     LABEL(srcloop)

        .p2align 4

LABEL(srcafter):

LABEL(64try):
        mov     _sref_(.amd64cache1half), %rcx
        cmp	%rdx, %rcx
        cmova   %rdx, %rcx

LABEL(64):                               /* 64-byte */
        shr     $6, %rcx
        jz      LABEL(32)

        .p2align 4

LABEL(64loop):
        mov        (%rsi), %rax
        mov      8 (%rsi),  %r8
        sub        (%rdi), %rax
        sub      8 (%rdi),  %r8
        or      %r8,  %rax

        mov     16 (%rsi),  %r9
        mov     24 (%rsi), %r10
        sub     16 (%rdi),  %r9
        sub     24 (%rdi), %r10
        or      %r10, %r9

        or      %r9,  %rax
        jnz     LABEL(32)

        mov     32 (%rsi), %rax
        mov     40 (%rsi),  %r8
        sub     32 (%rdi), %rax
        sub     40 (%rdi),  %r8
        or      %r8,  %rax

        mov     48 (%rsi),  %r9
        mov     56 (%rsi), %r10
        sub     48 (%rdi),  %r9
        sub     56 (%rdi), %r10
        or      %r10, %r9

        or      %r9,  %rax
        jnz    	LABEL(32)

        lea     64 (%rsi), %rsi
        lea     64 (%rdi), %rdi

        sub     $64, %rdx
        dec     %rcx
        jnz     LABEL(64loop)

LABEL(64skip):
        cmp     $2048, %rdx
        ja     LABEL(64after)

        test    %edx, %edx
        jnz     LABEL(32)

        xor     %eax, %eax
        ret

        .p2align 4

LABEL(64after):

LABEL(pretry):

LABEL(pre):                              /* 64-byte prefetching */
        mov     _sref_(.amd64cache2half), %rcx
        cmp	%rdx, %rcx
        cmova   %rdx, %rcx

        shr     $6, %rcx
        jz      LABEL(preskip)

        prefetchnta 512 (%rsi)	/* 3DNow: use prefetch */
        prefetchnta 512 (%rdi)	/* 3DNow: use prefetch */

        mov        (%rsi), %rax
        mov      8 (%rsi), %r9
        mov     16 (%rsi), %r10
        mov     24 (%rsi), %r11
        sub        (%rdi), %rax
        sub      8 (%rdi), %r9
        sub     16 (%rdi), %r10
        sub     24 (%rdi), %r11

        or       %r9, %rax
        or      %r11, %r10
        or      %r10, %rax
        jnz     LABEL(32)

        mov     32 (%rsi), %rax
        mov     40 (%rsi), %r9
        mov     48 (%rsi), %r10
        mov     56 (%rsi), %r11
        sub     32 (%rdi), %rax
        sub     40 (%rdi), %r9
        sub     48 (%rdi), %r10
        sub     56 (%rdi), %r11

        or       %r9, %rax
        or      %r11, %r10
        or      %r10, %rax
        jnz     LABEL(32)

        lea     64 (%rsi), %rsi
        lea     64 (%rdi), %rdi

        sub     $64, %rdx
        dec     %rcx

        .p2align 4

LABEL(preloop):
        prefetchnta 512 (%rsi)	/* 3DNow: use prefetch */
        prefetchnta 512 (%rdi)	/* 3DNow: use prefetch */

        mov        (%rsi), %rax
        mov      8 (%rsi), %r9
        mov     16 (%rsi), %r10
        mov     24 (%rsi), %r11
        sub        (%rdi), %rax
        sub      8 (%rdi), %r9
        sub     16 (%rdi), %r10
        sub     24 (%rdi), %r11

        or       %r9, %rax
        or      %r11, %r10
        or      %r10, %rax
        jnz     LABEL(32)

        mov     32 (%rsi), %rax
        mov     40 (%rsi), %r9
        mov     48 (%rsi), %r10
        mov     56 (%rsi), %r11
        sub     32 (%rdi), %rax
        sub     40 (%rdi), %r9
        sub     48 (%rdi), %r10
        sub     56 (%rdi), %r11

        or       %r9, %rax
        or      %r11, %r10
        or      %r10, %rax
        jnz     LABEL(32)

        lea     64 (%rsi), %rsi
        lea     64 (%rdi), %rdi

        sub     $64, %rdx
        dec     %rcx
        jnz     LABEL(preloop)


LABEL(preskip):
        cmp     $2048, %rdx
        ja      LABEL(preafter)

        test    %edx, %edx
        jnz     LABEL(32)

        xor     %eax, %eax
        ret

        .p2align 4

LABEL(preafter):

LABEL(128try):

LABEL(128):                              /* 128-byte */
        mov     %rdx, %rcx
        shr     $7, %rcx
        jz      LABEL(128skip)

        .p2align 4

LABEL(128loop):
        prefetchnta 512 (%rsi)	/* 3DNow: use prefetch */
        prefetchnta 512 (%rdi)	/* 3DNow: use prefetch */

        mov        (%rsi), %rax
        mov      8 (%rsi), %r8
        sub        (%rdi), %rax
        sub      8 (%rdi), %r8
        mov     16 (%rsi), %r9
        mov     24 (%rsi), %r10
        sub     16 (%rdi), %r9
        sub     24 (%rdi), %r10

        or       %r8, %rax
        or       %r9, %r10
        or      %r10, %rax

        mov     32 (%rsi), %r8
        mov     40 (%rsi), %r9
        sub     32 (%rdi), %r8
        sub     40 (%rdi), %r9
        mov     48 (%rsi), %r10
        mov     56 (%rsi), %r11
        sub     48 (%rdi), %r10
        sub     56 (%rdi), %r11

        or       %r9, %r8
        or      %r11, %r10
        or      %r10, %r8

        or      %r8, %rax
        jnz     LABEL(32)

        prefetchnta 576 (%rsi)	/* 3DNow: use prefetch */
        prefetchnta 576 (%rdi)	/* 3DNow: use prefetch */

        mov      64 (%rsi), %rax
        mov      72 (%rsi), %r8
        sub      64 (%rdi), %rax
        sub      72 (%rdi), %r8
        mov      80 (%rsi), %r9
        mov      88 (%rsi), %r10
        sub      80 (%rdi), %r9
        sub      88 (%rdi), %r10

        or       %r8, %rax
        or       %r9, %r10
        or      %r10, %rax

        mov      96 (%rsi), %r8
        mov     104 (%rsi), %r9
        sub      96 (%rdi), %r8
        sub     104 (%rdi), %r9
        mov     112 (%rsi), %r10
        mov     120 (%rsi), %r11
        sub     112 (%rdi), %r10
        sub     120 (%rdi), %r11

        or       %r9, %r8
        or      %r11, %r10
        or      %r10, %r8

        or      %r8, %rax
        jnz     LABEL(32)

        sub     $128, %rdx
        dec     %rcx

        lea     128 (%rsi), %rsi
        lea     128 (%rdi), %rdi

        jnz     LABEL(128loop)

LABEL(128skip):
        and     $127, %edx
        jnz     LABEL(32)

        xor     %eax, %eax
        ret

	SET_SIZE(memcmp)
