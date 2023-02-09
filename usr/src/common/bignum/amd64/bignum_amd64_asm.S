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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/asm_linkage.h>

#if defined(lint) || defined(__lint)

#include <sys/types.h>

/* ARGSUSED */
uint64_t
big_mul_set_vec(uint64_t *r, uint64_t *a, int len, uint64_t digit)
{ return (0); }

/* ARGSUSED */
uint64_t
big_mul_add_vec(uint64_t *r, uint64_t *a, int len, uint64_t digit)
{ return (0); }

/* ARGSUSED */
void
big_sqr_vec(uint64_t *r, uint64_t *a, int len)
{}

#else	/* lint */

/ ------------------------------------------------------------------------
/
/  Implementation of big_mul_set_vec which exploits
/  the 64X64->128 bit  unsigned multiply instruction.
/
/  As defined in Sun's bignum library for pkcs11, bignums are
/  composed of an array of 64-bit "digits" or "chunks" along with
/  descriptive information.
/
/ ------------------------------------------------------------------------

/ r = a * digit, r and a are vectors of length len
/ returns the carry digit
/ r and a are 64 bit aligned.
/
/ uint64_t
/ big_mul_set_vec(uint64_t *r, uint64_t *a, int len, uint64_t digit)
/
	ENTRY(big_mul_set_vec)
	xorq	%rax, %rax		/ if (len == 0) return (0)
	testq	%rdx, %rdx
	jz	.L17

	movq	%rdx, %r8		/ Use r8 for len; %rdx is used by mul
	xorq	%r9, %r9		/ cy = 0

.L15:
	cmpq	$8, %r8			/ 8 - len
	jb	.L16
	movq	0(%rsi), %rax		/ rax = a[0]
	movq	8(%rsi), %r11		/ prefetch a[1]
	mulq	%rcx			/ p = a[0] * digit
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 0(%rdi)		/ r[0] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)

	movq	%r11, %rax
	movq	16(%rsi), %r11		/ prefetch a[2]
	mulq	%rcx			/ p = a[1] * digit
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 8(%rdi)		/ r[1] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)

	movq	%r11, %rax
	movq	24(%rsi), %r11		/ prefetch a[3]
	mulq	%rcx			/ p = a[2] * digit
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 16(%rdi)		/ r[2] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)

	movq	%r11, %rax
	movq	32(%rsi), %r11		/ prefetch a[4]
	mulq	%rcx			/ p = a[3] * digit
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 24(%rdi)		/ r[3] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)

	movq	%r11, %rax
	movq	40(%rsi), %r11		/ prefetch a[5]
	mulq	%rcx			/ p = a[4] * digit
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 32(%rdi)		/ r[4] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)

	movq	%r11, %rax
	movq	48(%rsi), %r11		/ prefetch a[6]
	mulq	%rcx			/ p = a[5] * digit
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 40(%rdi)		/ r[5] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)

	movq	%r11, %rax
	movq	56(%rsi), %r11		/ prefetch a[7]
	mulq	%rcx			/ p = a[6] * digit
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 48(%rdi)		/ r[6] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)

	movq	%r11, %rax
	mulq	%rcx			/ p = a[7] * digit
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 56(%rdi)		/ r[7] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)

	addq	$64, %rsi
	addq	$64, %rdi
	subq	$8, %r8

	jz	.L17
	jmp	.L15

.L16:
	movq	0(%rsi), %rax
	mulq	%rcx			/ p = a[0] * digit
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 0(%rdi)		/ r[0] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)
	decq	%r8
	jz	.L17

	movq	8(%rsi), %rax
	mulq	%rcx			/ p = a[1] * digit
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 8(%rdi)		/ r[1] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)
	decq	%r8
	jz	.L17

	movq	16(%rsi), %rax
	mulq	%rcx			/ p = a[2] * digit
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 16(%rdi)		/ r[2] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)
	decq	%r8
	jz	.L17

	movq	24(%rsi), %rax
	mulq	%rcx			/ p = a[3] * digit
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 24(%rdi)		/ r[3] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)
	decq	%r8
	jz	.L17

	movq	32(%rsi), %rax
	mulq	%rcx			/ p = a[4] * digit
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 32(%rdi)		/ r[4] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)
	decq	%r8
	jz	.L17

	movq	40(%rsi), %rax
	mulq	%rcx			/ p = a[5] * digit
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 40(%rdi)		/ r[5] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)
	decq	%r8
	jz	.L17

	movq	48(%rsi), %rax
	mulq	%rcx			/ p = a[6] * digit
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 48(%rdi)		/ r[6] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)
	decq	%r8
	jz	.L17


.L17:
	movq	%r9, %rax
	ret
	SET_SIZE(big_mul_set_vec)


/ ------------------------------------------------------------------------
/
/  Implementation of big_mul_add_vec which exploits
/  the 64X64->128 bit  unsigned multiply instruction.
/
/  As defined in Sun's bignum library for pkcs11, bignums are
/  composed of an array of 64-bit "digits" or "chunks" along with
/  descriptive information.
/
/ ------------------------------------------------------------------------

/ r += a * digit, r and a are vectors of length len
/ returns the carry digit
/ r and a are 64 bit aligned.
/
/ uint64_t
/ big_mul_add_vec(uint64_t *r, uint64_t *a, int len, uint64_t digit)
/
	ENTRY(big_mul_add_vec)
	xorq	%rax, %rax		/ if (len == 0) return (0)
	testq	%rdx, %rdx
	jz	.L27

	movq	%rdx, %r8		/ Use r8 for len; %rdx is used by mul
	xorq	%r9, %r9		/ cy = 0

.L25:
	cmpq	$8, %r8			/ 8 - len
	jb	.L26
	movq	0(%rsi), %rax		/ rax = a[0]
	movq	0(%rdi), %r10		/ r10 = r[0]
	movq	8(%rsi), %r11		/ prefetch a[1]
	mulq	%rcx			/ p = a[0] * digit
	addq	%r10, %rax
	adcq	$0, %rdx		/ p += r[0]
	movq	8(%rdi), %r10		/ prefetch r[1]
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 0(%rdi)		/ r[0] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)

	movq	%r11, %rax
	movq	16(%rsi), %r11		/ prefetch a[2]
	mulq	%rcx			/ p = a[1] * digit
	addq	%r10, %rax
	adcq	$0, %rdx		/ p += r[1]
	movq	16(%rdi), %r10		/ prefetch r[2]
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 8(%rdi)		/ r[1] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)

	movq	%r11, %rax
	movq	24(%rsi), %r11		/ prefetch a[3]
	mulq	%rcx			/ p = a[2] * digit
	addq	%r10, %rax
	adcq	$0, %rdx		/ p += r[2]
	movq	24(%rdi), %r10		/ prefetch r[3]
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 16(%rdi)		/ r[2] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)

	movq	%r11, %rax
	movq	32(%rsi), %r11		/ prefetch a[4]
	mulq	%rcx			/ p = a[3] * digit
	addq	%r10, %rax
	adcq	$0, %rdx		/ p += r[3]
	movq	32(%rdi), %r10		/ prefetch r[4]
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 24(%rdi)		/ r[3] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)

	movq	%r11, %rax
	movq	40(%rsi), %r11		/ prefetch a[5]
	mulq	%rcx			/ p = a[4] * digit
	addq	%r10, %rax
	adcq	$0, %rdx		/ p += r[4]
	movq	40(%rdi), %r10		/ prefetch r[5]
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 32(%rdi)		/ r[4] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)

	movq	%r11, %rax
	movq	48(%rsi), %r11		/ prefetch a[6]
	mulq	%rcx			/ p = a[5] * digit
	addq	%r10, %rax
	adcq	$0, %rdx		/ p += r[5]
	movq	48(%rdi), %r10		/ prefetch r[6]
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 40(%rdi)		/ r[5] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)

	movq	%r11, %rax
	movq	56(%rsi), %r11		/ prefetch a[7]
	mulq	%rcx			/ p = a[6] * digit
	addq	%r10, %rax
	adcq	$0, %rdx		/ p += r[6]
	movq	56(%rdi), %r10		/ prefetch r[7]
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 48(%rdi)		/ r[6] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)

	movq	%r11, %rax
	mulq	%rcx			/ p = a[7] * digit
	addq	%r10, %rax
	adcq	$0, %rdx		/ p += r[7]
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 56(%rdi)		/ r[7] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)

	addq	$64, %rsi
	addq	$64, %rdi
	subq	$8, %r8

	jz	.L27
	jmp	.L25

.L26:
	movq	0(%rsi), %rax
	movq	0(%rdi), %r10
	mulq	%rcx			/ p = a[0] * digit
	addq	%r10, %rax
	adcq	$0, %rdx		/ p += r[0]
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 0(%rdi)		/ r[0] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)
	decq	%r8
	jz	.L27

	movq	8(%rsi), %rax
	movq	8(%rdi), %r10
	mulq	%rcx			/ p = a[1] * digit
	addq	%r10, %rax
	adcq	$0, %rdx		/ p += r[1]
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 8(%rdi)		/ r[1] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)
	decq	%r8
	jz	.L27

	movq	16(%rsi), %rax
	movq	16(%rdi), %r10
	mulq	%rcx			/ p = a[2] * digit
	addq	%r10, %rax
	adcq	$0, %rdx		/ p += r[2]
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 16(%rdi)		/ r[2] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)
	decq	%r8
	jz	.L27

	movq	24(%rsi), %rax
	movq	24(%rdi), %r10
	mulq	%rcx			/ p = a[3] * digit
	addq	%r10, %rax
	adcq	$0, %rdx		/ p += r[3]
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 24(%rdi)		/ r[3] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)
	decq	%r8
	jz	.L27

	movq	32(%rsi), %rax
	movq	32(%rdi), %r10
	mulq	%rcx			/ p = a[4] * digit
	addq	%r10, %rax
	adcq	$0, %rdx		/ p += r[4]
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 32(%rdi)		/ r[4] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)
	decq	%r8
	jz	.L27

	movq	40(%rsi), %rax
	movq	40(%rdi), %r10
	mulq	%rcx			/ p = a[5] * digit
	addq	%r10, %rax
	adcq	$0, %rdx		/ p += r[5]
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 40(%rdi)		/ r[5] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)
	decq	%r8
	jz	.L27

	movq	48(%rsi), %rax
	movq	48(%rdi), %r10
	mulq	%rcx			/ p = a[6] * digit
	addq	%r10, %rax
	adcq	$0, %rdx		/ p += r[6]
	addq	%r9, %rax
	adcq	$0, %rdx		/ p += cy
	movq	%rax, 48(%rdi)		/ r[6] = lo(p)
	movq	%rdx, %r9		/ cy = hi(p)
	decq	%r8
	jz	.L27


.L27:
	movq	%r9, %rax
	ret
	SET_SIZE(big_mul_add_vec)


/ void
/ big_sqr_vec(uint64_t *r, uint64_t *a, int len)

	ENTRY(big_sqr_vec)
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	pushq	%rdx			/ save arg3, len
	pushq	%rsi			/ save arg2, a
	pushq	%rdi			/ save arg1, r

	leaq	8(%rdi), %r13		/ tr = r + 1
	movq	%rsi, %r14		/ ta = a
	movq	%rdx, %r15		/ tlen = len
	decq	%r15			/ tlen = len - 1
	movq	%r13, %rdi		/ arg1 = tr
	leaq	8(%r14), %rsi		/ arg2 = ta + 1
	movq	%r15, %rdx		/ arg3 = tlen
	movq	0(%r14), %rcx		/ arg4 = ta[0]
	call	big_mul_set_vec
	movq	%rax, 0(%r13, %r15, 8)	/ tr[tlen] = cy
.L31:
	decq	%r15			/ --tlen
	jz	.L32			/ while (--tlen != 0)

	addq	$16, %r13		/ tr += 2
	addq	$8, %r14		/ ++ta
	movq	%r13, %rdi		/ arg1 = tr
	leaq	8(%r14), %rsi		/ arg2 = ta + 1
	movq	%r15, %rdx		/ arg3 = tlen
	movq	0(%r14), %rcx		/ arg4 = ta[0]
	call	big_mul_add_vec
	movq	%rax, 0(%r13, %r15, 8)	/ tr[tlen] = cy
	jmp	.L31

.L32:

/ No more function calls after this.
/ Restore arguments to registers.
/ However, don't use %rdx for arg3, len, because it is heavily
/ used by the hardware MUL instruction.  Use %r8, instead.
	movq	0(%rsp), %rdi		/ %rdi == arg1 == r
	movq	8(%rsp), %rsi		/ %rsi == arg2 == a
	movq	16(%rsp), %r8		/ %r8  == arg3 == len

	movq	0(%rsi), %rax		/ %rax = a[0];
	mulq	%rax			/ s = %edx:%eax = a[0]**2
	movq	%rax, 0(%rdi)		/ r[0] = lo64(s)
	movq	%rdx, %r9		/ cy = hi64(s)
	xorq	%rdx, %rdx
	movq	8(%rdi), %rax		/ p = %rdx:%rax = r[1]
	addq	%rax, %rax
	adcq	$0, %rdx		/ p = p << 1
	addq	%r9, %rax
	adcq	$0, %rdx		/ p = (r[1] << 1) + cy
	movq	%rax, 8(%rdi)		/ r[1] = lo64(p)
	movq	%rdx, %r9		/ cy = hi64(p)
	movq	$1, %r11		/ row = 1
	movq	$2, %r12		/ col = 2
	movq	%r8, %r15
	decq	%r15			/ tlen = len - 1
.L33:
	cmpq	%r8, %r11		/ len - row
	jae	.L34			/ while (row < len)

	movq	0(%rsi, %r11, 8), %rax	/ s = (uint128_t)a[row]
	mulq	%rax			/ s = s * s
	xorq	%rbx, %rbx
	movq	0(%rdi, %r12, 8), %rcx	/ p = (uint128_t)r[col]
	addq	%rcx, %rcx
	adcq	$0, %rbx		/ p = p << 1
	addq	%rcx, %rax
	adcq	%rbx, %rdx		/ t = p + s
	xorq	%r10, %r10
	movq	%rax, %rbp		/ t2 = 0:lo64(t)
	addq	%r9, %rbp
	adcq	$0, %r10		/ t2 = %r10:%rbp = lo64(t) + cy
	movq	%rbp, 0(%rdi, %r12, 8)	/ r[col] = lo64(t2)
	xorq	%rcx, %rcx
	movq	%rdx, %r9
	addq	%r10, %r9
	adcq	$0, %rcx		/ cy = hi64(t) + hi64(t2)
	cmpq	%r11, %r15
	je	.L34			/ if (row == len - 1) break
	xorq	%rdx, %rdx
	movq	8(%rdi, %r12, 8), %rax
	addq	%rax, %rax
	adcq	$0, %rdx
	addq	%r9, %rax
	adcq	%rcx, %rdx		/ p = (lo64(r[col+1]) << 1) + cy
	movq	%rax, 8(%rdi, %r12, 8)	/ r[col+1] = lo64(p)
	movq	%rdx, %r9		/ cy = hi64(p)

	incq	%r11			/ ++row
	addq	$2, %r12		/ col += 2
	jmp	.L33

.L34:
	movq	%r9, 8(%rdi, %r12, 8)	/ r[col+1] = lo64(cy)

	addq	$24, %rsp		/ skip %rdi, %rsi, %rdx
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx

	ret

	SET_SIZE(big_sqr_vec)

#endif	/* lint */
