/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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

	ANSI_PRAGMA_WEAK(memmove,function)
	ANSI_PRAGMA_WEAK(memcpy,function)

#include "SYS.h"
#include "cache.h"

	ANSI_PRAGMA_WEAK2(_private_memcpy,memcpy,function)

#define LABEL(s) .memcpy/**/s

	ENTRY(memmove)		/* (void *s1, void *s2, size_t n) */
	cmpq	%rsi,%rdi	/ if (source addr > dest addr)
	leaq	-1(%rsi,%rdx),%r9
	jle	.CopyRight	/ 
	cmpq	%r9,%rdi
	jle	.CopyLeft
	jmp	.CopyRight

	ENTRY(memcpy)                        /* (void *, const void*, size_t) */

.CopyRight:
LABEL(1try):
        cmp     $16, %rdx
        mov     %rdi, %rax
        jae     LABEL(1after)

        .p2align 4

LABEL(1):				/* 1-byte */
        test    $1, %dl
        jz      LABEL(1a)

        mov     (%rsi), %cl
        mov     %cl, (%rdi)

	dec	%dl
	lea	1 (%rsi), %rsi
	lea	1 (%rdi), %rdi
	jz	LABEL(exit)

        .p2align 4,, 4

LABEL(1a):
        test    $2, %dl
        jz      LABEL(1b)

        mov     (%rsi), %cx
        mov     %cx, (%rdi)

	sub	$2, %dl
	lea	2 (%rsi), %rsi
	lea	2 (%rdi), %rdi
	jz	LABEL(exit)

        .p2align 4,, 4

LABEL(1b):
        test    $4, %dl
        jz      LABEL(1c)

        mov     (%rsi), %ecx
        mov     %ecx, (%rdi)

/*	sub	$4, %dl */
	lea	4 (%rsi), %rsi
	lea	4 (%rdi), %rdi
/*	jz	LABEL(exit) */

        .p2align 4,, 4

LABEL(1c):
        test    $8, %dl
        jz      LABEL(1d)

        mov     (%rsi), %rcx
        mov     %rcx, (%rdi)

/*	sub	$8, %dl */
/*	lea	8 (%rsi), %rsi */
/*	lea	8 (%rdi), %rdi */
/*	jz	LABEL(exit) */

        .p2align 4

LABEL(1d):

LABEL(exit):
        rep
        ret

        .p2align 4

LABEL(1after):
        push    %rax

LABEL(8try):
        cmp     $32, %rdx
        jae     LABEL(8after)

LABEL(8):                        /* 8-byte */
        mov     %edx, %ecx
        shr     $3, %ecx
        jz      LABEL(8skip)

        .p2align 4

LABEL(8loop):
        dec     %ecx

        mov     (%rsi), %rax
        mov     %rax, (%rdi)

        lea     8 (%rsi), %rsi
        lea     8 (%rdi), %rdi

        jnz     LABEL(8loop)

LABEL(8skip):
        and     $7, %edx
        pop     %rax
        jnz     LABEL(1)

        rep
        ret

        .p2align 4

LABEL(8after):

LABEL(32try):
	mov	$512, %r8d		/* size for unaligned data */
	mov	$4096, %r9d		/* size for aligned data */
	test	$7, %esi		/* check if either source.. */
	cmovz	%r9, %r8
	test	$7, %edi		/* .. or destination is aligned */
	cmovz	%r9, %r8

        cmp     %r8, %rdx
        ja	LABEL(32after)

LABEL(32):				/* 32-byte */
        mov     %edx, %ecx
        shr     $5, %ecx
        jz      LABEL(32skip)

        .p2align 4

LABEL(32loop):
        dec     %ecx

        mov        (%rsi), %rax
        mov      8 (%rsi), %r8
        mov     16 (%rsi), %r9
        mov     24 (%rsi), %r10

        mov     %rax,    (%rdi)
        mov      %r8,  8 (%rdi)
        mov      %r9, 16 (%rdi)
        mov     %r10, 24 (%rdi)

        lea     32 (%rsi), %rsi
        lea     32 (%rdi), %rdi

        jz      LABEL(32skip)

        dec     %ecx

        mov        (%rsi), %rax
        mov      8 (%rsi), %r8
        mov     16 (%rsi), %r9
        mov     24 (%rsi), %r10

        mov     %rax,    (%rdi)
        mov      %r8,  8 (%rdi)
        mov      %r9, 16 (%rdi)
        mov     %r10, 24 (%rdi)

        lea     32 (%rsi), %rsi
        lea     32 (%rdi), %rdi

        jnz     LABEL(32loop)

        .p2align 4

LABEL(32skip):
        and     $31, %edx
        jnz     LABEL(8)

        pop     %rax
        ret

        .p2align 4

LABEL(32after):

	/* 3DNow: use prefetch */
	prefetchnta _sref_(.amd64cache1) /* improves test further ahead on B0 */

LABEL(aligntry):
        mov     %edi, %r8d      	/* align by destination */

        and	$7, %r8d
        jz      LABEL(alignafter)  	/* not unaligned */

LABEL(align):                      	/* align */
        lea     -8 (%r8, %rdx), %rdx
        sub     $8, %r8d

        .p2align 4

LABEL(alignloop):
        inc     %r8d

        mov     (%rsi), %al
        mov     %al, (%rdi)

        lea     1 (%rsi), %rsi
        lea     1 (%rdi), %rdi

        jnz     LABEL(alignloop)

        .p2align 4

LABEL(alignafter):
        mov     _sref_(.amd64cache1half), %r11
        cmp     %rdx, %r11
        cmova   %rdx, %r11

LABEL(fast):
	mov	%r11, %rcx
	and	$-8, %r11
	shr	$3, %rcx
/*	jz	LABEL(fastskip) */

	rep				/* good ol' MOVS */
	movsq

LABEL(fastskip):
	sub	%r11, %rdx
	test	$-8, %rdx
	jnz	LABEL(fastafterlater)

	and	$7, %edx
	pop	%rax
	jnz	LABEL(1)

	rep
	ret

        .p2align 4

LABEL(64try):
        mov     _sref_(.amd64cache1half), %r11
        cmp     %rdx, %r11
        cmova   %rdx, %r11

LABEL(64):                               /* 64-byte */
        mov     %r11, %rcx
        and     $-64, %r11
        shr     $6, %rcx
        jz      LABEL(64skip)

        .p2align 4

LABEL(64loop):
        dec     %ecx

        mov        (%rsi), %rax
        mov      8 (%rsi), %r8
        mov     16 (%rsi), %r9
        mov     24 (%rsi), %r10

        mov     %rax,    (%rdi)
        mov      %r8,  8 (%rdi)
        mov      %r9, 16 (%rdi)
        mov     %r10, 24 (%rdi)

        mov     32 (%rsi), %rax
        mov     40 (%rsi), %r8
        mov     48 (%rsi), %r9
        mov     56 (%rsi), %r10

        mov     %rax, 32 (%rdi)
        mov      %r8, 40 (%rdi)
        mov      %r9, 48 (%rdi)
        mov     %r10, 56 (%rdi)

        lea     64 (%rsi), %rsi
        lea     64 (%rdi), %rdi

        jz      LABEL(64skip)

        dec     %ecx

        mov        (%rsi), %rax
        mov      8 (%rsi), %r8
        mov     16 (%rsi), %r9
        mov     24 (%rsi), %r10

        mov     %rax,    (%rdi)
        mov      %r8,  8 (%rdi)
        mov      %r9, 16 (%rdi)
        mov     %r10, 24 (%rdi)

        mov     32 (%rsi), %rax
        mov     40 (%rsi), %r8
        mov     48 (%rsi), %r9
        mov     56 (%rsi), %r10

        mov     %rax, 32 (%rdi)
        mov      %r8, 40 (%rdi)
        mov      %r9, 48 (%rdi)
        mov     %r10, 56 (%rdi)

        lea     64 (%rsi), %rsi
        lea     64 (%rdi), %rdi

        jnz     LABEL(64loop)

        .p2align 4

LABEL(64skip):
        sub     %r11, %rdx
        test    $-64, %rdx
        jnz     LABEL(64after)

        and     $63, %edx
        jnz     LABEL(32)

        pop     %rax
        ret

        .p2align 4

LABEL(64after):

LABEL(fastafterlater):

LABEL(pretry):
        mov     _sref_(.amd64cache2half), %r8
        cmp     %rdx, %r8
        cmova   %rdx, %r8

LABEL(pre):                              /* 64-byte prefetching */
        mov     %r8, %rcx
        and     $-64, %r8
        shr     $6, %rcx
        jz      LABEL(preskip)

        push    %r14
        push    %r13
        push    %r12
        push    %rbx

        .p2align 4

LABEL(preloop):
        dec     %rcx

        mov        (%rsi), %rax
        mov      8 (%rsi), %rbx
        mov     16 (%rsi), %r9
        mov     24 (%rsi), %r10
        mov     32 (%rsi), %r11
        mov     40 (%rsi), %r12
        mov     48 (%rsi), %r13
        mov     56 (%rsi), %r14

        prefetchnta  0 + 896 (%rsi)	/* 3DNow: use prefetch */
        prefetchnta 64 + 896 (%rsi)	/* 3DNow: use prefetch */

        mov     %rax,    (%rdi)
        mov     %rbx,  8 (%rdi)
        mov      %r9, 16 (%rdi)
        mov     %r10, 24 (%rdi)
        mov     %r11, 32 (%rdi)
        mov     %r12, 40 (%rdi)
        mov     %r13, 48 (%rdi)
        mov     %r14, 56 (%rdi)

        lea     64 (%rsi), %rsi
        lea     64 (%rdi), %rdi

        jz      LABEL(preskipa)

        dec     %rcx

        mov        (%rsi), %rax
        mov      8 (%rsi), %rbx
        mov     16 (%rsi), %r9
        mov     24 (%rsi), %r10
        mov     32 (%rsi), %r11
        mov     40 (%rsi), %r12
        mov     48 (%rsi), %r13
        mov     56 (%rsi), %r14

        mov     %rax,    (%rdi)
        mov     %rbx,  8 (%rdi)
        mov      %r9, 16 (%rdi)
        mov     %r10, 24 (%rdi)
        mov     %r11, 32 (%rdi)
        mov     %r12, 40 (%rdi)
        mov     %r13, 48 (%rdi)
        mov     %r14, 56 (%rdi)

        prefetchnta -64 + 896 (%rdi)	/* 3DNow: use prefetchw */
        prefetchnta   0 + 896 (%rdi)	/* 3DNow: use prefetchw */

        lea     64 (%rsi), %rsi
        lea     64 (%rdi), %rdi

        jnz     LABEL(preloop)

LABEL(preskipa):
        pop     %rbx
        pop     %r12
        pop     %r13
        pop     %r14


LABEL(preskip):
        sub     %r8, %rdx
        test    $-64, %rdx
        jnz     LABEL(preafter)

        and     $63, %edx
        jnz     LABEL(32)

        pop     %rax
        ret

        .p2align 4

LABEL(preafter):

LABEL(NTtry):

LABEL(NT):                               /* NT 64-byte */
        mov     %rdx, %rcx
        shr     $7, %rcx
        jz      LABEL(NTskip)

        push    %r14
        push    %r13
        push    %r12

       .p2align 4

LABEL(NTloop):
        prefetchnta 768 (%rsi)		/* prefetching NT here is not so good on B0 and C0 MP systems */
        prefetchnta 832 (%rsi)

        dec     %rcx

        mov        (%rsi), %rax
        mov      8 (%rsi), %r8
        mov     16 (%rsi), %r9
        mov     24 (%rsi), %r10
        mov     32 (%rsi), %r11
        mov     40 (%rsi), %r12
        mov     48 (%rsi), %r13
        mov     56 (%rsi), %r14

        movnti  %rax,    (%rdi)
        movnti   %r8,  8 (%rdi)
        movnti   %r9, 16 (%rdi)
        movnti  %r10, 24 (%rdi)
        movnti  %r11, 32 (%rdi)
        movnti  %r12, 40 (%rdi)
        movnti  %r13, 48 (%rdi)
        movnti  %r14, 56 (%rdi)

        mov      64 (%rsi), %rax
        mov      72 (%rsi), %r8
        mov      80 (%rsi), %r9
        mov      88 (%rsi), %r10
        mov      96 (%rsi), %r11
        mov     104 (%rsi), %r12
        mov     112 (%rsi), %r13
        mov     120 (%rsi), %r14

        movnti  %rax,  64 (%rdi)
        movnti   %r8,  72 (%rdi)
        movnti   %r9,  80 (%rdi)
        movnti  %r10,  88 (%rdi)
        movnti  %r11,  96 (%rdi)
        movnti  %r12, 104 (%rdi)
        movnti  %r13, 112 (%rdi)
        movnti  %r14, 120 (%rdi)

        lea     128 (%rsi), %rsi
        lea     128 (%rdi), %rdi

        jnz     LABEL(NTloop)

        mfence

        pop     %r12
        pop     %r13
        pop     %r14

LABEL(NTskip):
        and     $127, %edx
        jnz     LABEL(32)

        pop     %rax
        ret

	SET_SIZE(memcpy)                   /* (void *, const void*, size_t) */

.CopyLeft:
	movq	%rdi,%rax		/ set up return value
	movq	$7,%r8			/ heavily used constant
	movq	%rdx,%rcx		/ put len into %rcx for rep
	std				/ reverse direction bit (RtoL)
	cmpq	$24,%rcx		/ if (size < 24)
	ja	.BigCopyLeft		/ {
	movq	%r9,%rsi		/     src = src + size - 1
	leaq	-1(%rcx,%rdi),%rdi	/     dst = dst + size - 1
	rep;	smovb			/    do the byte copy
	cld				/    reset direction flag to LtoR
	ret				/  return(dba);
.BigCopyLeft:				/ } else {
	xchgq	%r9,%rcx
	movq	%rcx,%rsi		/ align source w/byte copy
	leaq	-1(%r9,%rdi),%rdi
	andq	%r8,%rcx
	jz	.SkipAlignLeft
	addq	$1, %rcx		/ we need to insure that future
	subq	%rcx,%r9		/ copy is done on aligned boundary
	rep;	smovb
.SkipAlignLeft:
	movq	%r9,%rcx	
	subq	%r8,%rsi
	shrq	$3,%rcx			/ do 8 byte copy RtoL
	subq	%r8,%rdi
	rep;	smovq
	andq	%r8,%r9		/ do 1 byte copy whats left
	jz	.CleanupReturnLeft
	movq	%r9,%rcx	
	addq	%r8,%rsi		/ rep; smovl instruction will decrement
	addq	%r8,%rdi		/ %rdi, %rsi by four after each copy
					/ adding 3 will restore pointers to byte
					/ before last double word copied
					/ which is where they are expected to
					/ be for the single byte copy code
	rep;	smovb
.CleanupReturnLeft:
	cld				/ reset direction flag to LtoR
	ret				/ return(dba);
	SET_SIZE(memmove)
