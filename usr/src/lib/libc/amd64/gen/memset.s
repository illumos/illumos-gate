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

	.ident	"%Z%%M%	%I%	%E% SMI"

	.file	"%M%"

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(memset,function)

#include "SYS.h"
#include "cache.h"

	ANSI_PRAGMA_WEAK2(_private_memset,memset,function)

#define LABEL(s) .memset/**/s

	ENTRY(memset)                	/* (void *, const void*, size_t) */

	mov	$0x0101010101010101, %rcx /* memset is itself */
        movzx   %sil, %rsi
        imul    %rcx, %rsi		/* replicate 8 times */

LABEL(try1):
        cmp     $64, %rdx
        mov     %rdi, %rax		/* return memory block address (even for bzero ()) */
        jae	LABEL(1after)

LABEL(1):                                /* 1-byte */
        test    $1, %dl
        jz      LABEL(1a)

        mov     %sil, (%rdi)
        inc	%rdi

LABEL(1a):
        test    $2, %dl
        jz      LABEL(1b)

        mov     %si, (%rdi)
        add	$2, %rdi

LABEL(1b):
        test    $4, %dl
        jz      LABEL(1c)

        mov     %esi, (%rdi)
	add	$4, %rdi

LABEL(1c):
        test    $8, %dl
        jz      LABEL(1d)

        mov     %rsi, (%rdi)
	add	$8, %rdi

LABEL(1d):
        test    $16, %dl
        jz      LABEL(1e)

        mov     %rsi,   (%rdi)
        mov     %rsi, 8 (%rdi)
	add	$16, %rdi

LABEL(1e):

        test    $32, %dl
        jz      LABEL(1f)

        mov     %rsi,    (%rdi)
        mov     %rsi,  8 (%rdi)
        mov     %rsi, 16 (%rdi)
        mov     %rsi, 24 (%rdi)
/*	add	$32, %rdi */

LABEL(1f):

LABEL(exit):
        rep
        ret

        .p2align 4

LABEL(1after):

LABEL(32try):
        cmp     $256, %rdx
        ja     LABEL(32after)

LABEL(32):                               /* 32-byte */
        mov     %edx, %ecx
        shr     $5, %ecx
        jz      LABEL(32skip)

        .p2align 4

LABEL(32loop):
        dec     %ecx

        mov     %rsi,    (%rdi)
        mov     %rsi,  8 (%rdi)
        mov     %rsi, 16 (%rdi)
        mov     %rsi, 24 (%rdi)

        lea     32 (%rdi), %rdi

        jz      LABEL(32skip)

        dec     %ecx

        mov     %rsi,    (%rdi)
        mov     %rsi,  8 (%rdi)
        mov     %rsi, 16 (%rdi)
        mov     %rsi, 24 (%rdi)

        lea     32 (%rdi), %rdi

        jnz     LABEL(32loop)

        .p2align 4

LABEL(32skip):
        and     $31, %edx
        jnz     LABEL(1)

        rep
        ret

        .p2align 4

LABEL(32after):

	/* 3DNow: use prefetch */
	prefetchnta _sref_(.amd64cache1) /* improves test further ahead on B0 */

LABEL(aligntry):
        mov     %edi, %ecx              /* align by destination */

        and     $7, %ecx                /* skip if already aligned */
        jz      LABEL(alignafter)

LABEL(align):                            /* align */
        lea     -8 (%rcx, %rdx), %rdx
        sub     $8, %ecx

        .p2align 4

LABEL(alignloop):
        inc     %ecx

        mov     %sil, (%rdi)
        lea     1 (%rdi), %rdi

        jnz     LABEL(alignloop)

        .p2align 4

LABEL(alignafter):
        mov	_sref_(.amd64cache2), %r8
        cmp     %rdx, %r8
        cmova   %rdx, %r8

	cmp	$2048, %rdx		/* this is slow for some block sizes */
	jb	LABEL(64)

LABEL(fast):				/* microcode */
	mov	%r8, %rcx
	and	$-8, %r8
	shr	$3, %rcx
/*	jz	LABEL(fastskip) */

	xchg	%rax, %rsi

	rep
	stosq

	xchg	%rax, %rsi

LABEL(fastskip):
	sub	%r8, %rdx
	ja	LABEL(64after)

	and	$7, %edx
	jnz	LABEL(1)

	rep
	ret

	.p2align 4

LABEL(64try):

LABEL(64):                               /* 64-byte */
        mov     %r8, %rcx
        and     $-64, %r8
        shr     $6, %rcx

        dec     %rcx                    /* this iteration starts the prefetcher sooner */

        mov     %rsi,    (%rdi)
        mov     %rsi,  8 (%rdi)
        mov     %rsi, 16 (%rdi)
        mov     %rsi, 24 (%rdi)
        mov     %rsi, 32 (%rdi)
        mov     %rsi, 40 (%rdi)
        mov     %rsi, 48 (%rdi)
        mov     %rsi, 56 (%rdi)

        lea     64 (%rdi), %rdi

        .p2align 4

LABEL(64loop):
        dec     %rcx

        mov     %rsi,    (%rdi)
        mov     %rsi,  8 (%rdi)
        mov     %rsi, 16 (%rdi)
        mov     %rsi, 24 (%rdi)
        mov     %rsi, 32 (%rdi)
        mov     %rsi, 40 (%rdi)
        mov     %rsi, 48 (%rdi)
        mov     %rsi, 56 (%rdi)

        lea     64 (%rdi), %rdi

        jnz     LABEL(64loop)

LABEL(64skip):
        sub     %r8, %rdx
        ja      LABEL(64after)

	and     $63, %edx
	jnz     LABEL(32)

        rep
        ret

        .p2align 4

LABEL(64after):

LABEL(NTtry):

LABEL(NT):                               /* 128-byte */
        mov     %rdx, %rcx
        shr     $7, %rcx
        jz      LABEL(NTskip)

        .p2align 4

LABEL(NTloop):                  /* on an MP system it would be better to prefetchnta 320 (%rdi) and 384 (%rdi) here, but not so on an 1P system */
        dec     %rcx

        movnti  %rsi,     (%rdi)
        movnti  %rsi,   8 (%rdi)
        movnti  %rsi,  16 (%rdi)
        movnti  %rsi,  24 (%rdi)
        movnti  %rsi,  32 (%rdi)
        movnti  %rsi,  40 (%rdi)
        movnti  %rsi,  48 (%rdi)
        movnti  %rsi,  56 (%rdi)
        movnti  %rsi,  64 (%rdi)
        movnti  %rsi,  72 (%rdi)
        movnti  %rsi,  80 (%rdi)
        movnti  %rsi,  88 (%rdi)
        movnti  %rsi,  96 (%rdi)
        movnti  %rsi, 104 (%rdi)
        movnti  %rsi, 112 (%rdi)
        movnti  %rsi, 120 (%rdi)

        lea     128 (%rdi), %rdi

        jnz     LABEL(NTloop)

        mfence

LABEL(NTskip):
        and     $127, %edx
        jnz     LABEL(32)

        rep
        ret

	SET_SIZE(memset)
