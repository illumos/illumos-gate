/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*-
 * Copyright (c) 1993 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/amd64/amd64/support.S,v 1.102 2003/10/02 05:08:13 alc Exp $
 */

#include <sys/asm_linkage.h>

#if defined(__lint)

/*
 * Overlapping bcopy (source and target may overlap arbitrarily).
 */
/* ARGSUSED */
void
ovbcopy(const void *from, void *to, size_t count)
{}

#else	/* __lint */

/*
 * Adapted from fbsd bcopy().
 *
 * bcopy(src, dst, cnt)
 *       rdi, rsi, rdx
 *  ws@tools.de     (Wolfgang Solfrank, TooLs GmbH) +49-228-985800
 */

#if defined(__amd64)

	ENTRY(ovbcopy)
	xchgq	%rsi,%rdi
	movq	%rdx,%rcx

	movq	%rdi,%rax
	subq	%rsi,%rax
	cmpq	%rcx,%rax		/* overlapping && src < dst? */
	jb	reverse

	shrq	$3,%rcx			/* copy by 64-bit words */
	cld				/* nope, copy forwards */
	rep
	movsq
	movq	%rdx,%rcx
	andq	$7,%rcx			/* any bytes left? */
	rep
	movsb
	ret

reverse:
	addq	%rcx,%rdi		/* copy backwards */
	addq	%rcx,%rsi
	decq	%rdi
	decq	%rsi
	andq	$7,%rcx			/* any fractional bytes? */
	std
	rep
	movsb
	movq	%rdx,%rcx		/* copy remainder by 32-bit words */
	shrq	$3,%rcx
	subq	$7,%rsi
	subq	$7,%rdi
	rep
	movsq
	cld
	ret
	SET_SIZE(ovbcopy)

#elif defined(__i386)

	ENTRY(ovbcopy)
	pushl	%esi
	pushl	%edi
	movl	12(%esp),%esi
	movl	16(%esp),%edi
	movl	20(%esp),%ecx

	movl	%edi,%eax
	subl	%esi,%eax
	cmpl	%ecx,%eax		/* overlapping && src < dst? */
	jb	reverse

	shrl	$2,%ecx			/* copy by 32-bit words */
	cld				/* nope, copy forwards */
	rep
	movsl
	movl	20(%esp),%ecx
	andl	$3,%ecx			/* any bytes left? */
	rep
	movsb
	popl	%edi
	popl	%esi
	ret

reverse:
	addl	%ecx,%edi		/* copy backwards */
	addl	%ecx,%esi
	decl	%edi
	decl	%esi
	andl	$3,%ecx			/* any fractional bytes? */
	std
	rep
	movsb
	movl	20(%esp),%ecx		/* copy remainder by 32-bit words */
	shrl	$2,%ecx
	subl	$3,%esi
	subl	$3,%edi
	rep
	movsl
	popl	%edi
	popl	%esi
	cld
	ret
	SET_SIZE(ovbcopy)

#endif	/* __i386 */

#endif	/* __lint */
