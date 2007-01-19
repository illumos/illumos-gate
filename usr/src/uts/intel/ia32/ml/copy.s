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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*       Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*       Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T		*/
/*         All Rights Reserved						*/

/*       Copyright (c) 1987, 1988 Microsoft Corporation			*/
/*         All Rights Reserved						*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/errno.h>
#include <sys/asm_linkage.h>

#if defined(__lint)
#include <sys/types.h>
#include <sys/systm.h>
#else	/* __lint */
#include "assym.h"
#endif	/* __lint */

#define	KCOPY_MIN_SIZE	128	/* Must be >= 16 bytes */
#define	XCOPY_MIN_SIZE	128	/* Must be >= 16 bytes */
/*
 * Non-temopral access (NTA) alignment requirement
 */
#define	NTA_ALIGN_SIZE	4	/* Must be at least 4-byte aligned */
#define	NTA_ALIGN_MASK	_CONST(NTA_ALIGN_SIZE-1)
#define	COUNT_ALIGN_SIZE	16	/* Must be at least 16-byte aligned */
#define	COUNT_ALIGN_MASK	_CONST(COUNT_ALIGN_SIZE-1)

/*
 * Copy a block of storage, returning an error code if `from' or
 * `to' takes a kernel pagefault which cannot be resolved.
 * Returns errno value on pagefault error, 0 if all ok
 */

#if defined(__lint)

/* ARGSUSED */
int
kcopy(const void *from, void *to, size_t count)
{ return (0); }

#else	/* __lint */

	.globl	kernelbase
	.globl	postbootkernelbase

#if defined(__amd64)

	ENTRY(kcopy)
	pushq	%rbp
	movq	%rsp, %rbp
#ifdef DEBUG
	cmpq	postbootkernelbase(%rip), %rdi 		/* %rdi = from */
	jb	0f
	cmpq	postbootkernelbase(%rip), %rsi		/* %rsi = to */
	jnb	1f
0:	leaq	.kcopy_panic_msg(%rip), %rdi
	xorl	%eax, %eax
	call	panic
1:
#endif
	/*
	 * pass lofault value as 4th argument to do_copy_fault
	 */
	leaq	_kcopy_copyerr(%rip), %rcx
	movq	%gs:CPU_THREAD, %r9	/* %r9 = thread addr */

do_copy_fault:
	movq	T_LOFAULT(%r9), %r11	/* save the current lofault */
	movq	%rcx, T_LOFAULT(%r9)	/* new lofault */

	xchgq	%rdi, %rsi		/* %rsi = source, %rdi = destination */
	movq	%rdx, %rcx		/* %rcx = count */
	shrq	$3, %rcx		/* 8-byte word count */
	rep
	  smovq

	movq	%rdx, %rcx
	andq	$7, %rcx		/* bytes left over */
	rep
	  smovb
	xorl	%eax, %eax		/* return 0 (success) */

	/*
	 * A fault during do_copy_fault is indicated through an errno value
	 * in %rax and we iretq from the trap handler to here.
	 */
_kcopy_copyerr:
	movq	%r11, T_LOFAULT(%r9)	/* restore original lofault */
	leave
	ret
	SET_SIZE(kcopy)

#elif defined(__i386)

#define	ARG_FROM	8
#define	ARG_TO		12
#define	ARG_COUNT	16

	ENTRY(kcopy)
#ifdef DEBUG
	pushl	%ebp
	movl	%esp, %ebp
	movl	postbootkernelbase, %eax
	cmpl	%eax, ARG_FROM(%ebp)
	jb	0f
	cmpl	%eax, ARG_TO(%ebp)
	jnb	1f
0:	pushl	$.kcopy_panic_msg
	call	panic
1:	popl	%ebp
#endif
	lea	_kcopy_copyerr, %eax	/* lofault value */
	movl	%gs:CPU_THREAD, %edx	

do_copy_fault:
	pushl	%ebp
	movl	%esp, %ebp		/* setup stack frame */
	pushl	%esi
	pushl	%edi			/* save registers */

	movl	T_LOFAULT(%edx), %edi
	pushl	%edi			/* save the current lofault */
	movl	%eax, T_LOFAULT(%edx)	/* new lofault */

	movl	ARG_COUNT(%ebp), %ecx
	movl	ARG_FROM(%ebp), %esi
	movl	ARG_TO(%ebp), %edi
	shrl	$2, %ecx		/* word count */
	rep
	  smovl
	movl	ARG_COUNT(%ebp), %ecx
	andl	$3, %ecx		/* bytes left over */
	rep
	  smovb
	xorl	%eax, %eax

	/*
	 * A fault during do_copy_fault is indicated through an errno value
	 * in %eax and we iret from the trap handler to here.
	 */
_kcopy_copyerr:
	popl	%ecx
	popl	%edi
	movl	%ecx, T_LOFAULT(%edx)	/* restore the original lofault */
	popl	%esi
	popl	%ebp
	ret
	SET_SIZE(kcopy)

#undef	ARG_FROM
#undef	ARG_TO
#undef	ARG_COUNT

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

/*
 * Copy a block of storage.  Similar to kcopy but uses non-temporal
 * instructions.
 */

/* ARGSUSED */
int
kcopy_nta(const void *from, void *to, size_t count, int copy_cached)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

#define	COPY_LOOP_INIT(src, dst, cnt)	\
	addq	cnt, src;			\
	addq	cnt, dst;			\
	shrq	$3, cnt;			\
	neg	cnt

	/* Copy 16 bytes per loop.  Uses %rax and %r8 */
#define	COPY_LOOP_BODY(src, dst, cnt)	\
	prefetchnta	0x100(src, cnt, 8);	\
	movq	(src, cnt, 8), %rax;		\
	movq	0x8(src, cnt, 8), %r8;		\
	movnti	%rax, (dst, cnt, 8);		\
	movnti	%r8, 0x8(dst, cnt, 8);		\
	addq	$2, cnt

	ENTRY(kcopy_nta)
	pushq	%rbp
	movq	%rsp, %rbp
#ifdef DEBUG
	cmpq	postbootkernelbase(%rip), %rdi 		/* %rdi = from */
	jb	0f
	cmpq	postbootkernelbase(%rip), %rsi		/* %rsi = to */
	jnb	1f
0:	leaq	.kcopy_panic_msg(%rip), %rdi
	xorl	%eax, %eax
	call	panic
1:
#endif

	movq	%gs:CPU_THREAD, %r9
	cmpq	$0, %rcx		/* No non-temporal access? */
	/*
	 * pass lofault value as 4th argument to do_copy_fault
	 */
	leaq	_kcopy_nta_copyerr(%rip), %rcx	/* doesn't set rflags */
	jnz	do_copy_fault		/* use regular access */
	/*
	 * Make sure cnt is >= KCOPY_MIN_SIZE
	 */
	cmpq	$KCOPY_MIN_SIZE, %rdx
	jb	do_copy_fault

	/*
	 * Make sure src and dst are NTA_ALIGN_SIZE aligned,
	 * count is COUNT_ALIGN_SIZE aligned.
	 */
	movq	%rdi, %r10
	orq	%rsi, %r10
	andq	$NTA_ALIGN_MASK, %r10
	orq	%rdx, %r10
	andq	$COUNT_ALIGN_MASK, %r10
	jnz	do_copy_fault

	ALTENTRY(do_copy_fault_nta)
	movq    %gs:CPU_THREAD, %r9     /* %r9 = thread addr */
	movq    T_LOFAULT(%r9), %r11    /* save the current lofault */
	movq    %rcx, T_LOFAULT(%r9)    /* new lofault */

	/*
	 * COPY_LOOP_BODY uses %rax and %r8
	 */
	COPY_LOOP_INIT(%rdi, %rsi, %rdx)
2:	COPY_LOOP_BODY(%rdi, %rsi, %rdx)
	jnz	2b

	mfence
	xorl	%eax, %eax		/* return 0 (success) */

_kcopy_nta_copyerr:
	movq	%r11, T_LOFAULT(%r9)    /* restore original lofault */
	leave
	ret
	SET_SIZE(do_copy_fault_nta)
	SET_SIZE(kcopy_nta)

#elif defined(__i386)

#define	ARG_FROM	8
#define	ARG_TO		12
#define	ARG_COUNT	16

#define	COPY_LOOP_INIT(src, dst, cnt)	\
	addl	cnt, src;			\
	addl	cnt, dst;			\
	shrl	$3, cnt;			\
	neg	cnt

#define	COPY_LOOP_BODY(src, dst, cnt)	\
	prefetchnta	0x100(src, cnt, 8);	\
	movl	(src, cnt, 8), %esi;		\
	movnti	%esi, (dst, cnt, 8);		\
	movl	0x4(src, cnt, 8), %esi;		\
	movnti	%esi, 0x4(dst, cnt, 8);		\
	movl	0x8(src, cnt, 8), %esi;		\
	movnti	%esi, 0x8(dst, cnt, 8);		\
	movl	0xc(src, cnt, 8), %esi;		\
	movnti	%esi, 0xc(dst, cnt, 8);		\
	addl	$2, cnt

	/*
	 * kcopy_nta is not implemented for 32-bit as no performance
	 * improvement was shown.  We simply jump directly to kcopy
	 * and discard the 4 arguments.
	 */
	ENTRY(kcopy_nta)
	jmp	kcopy

	lea	_kcopy_nta_copyerr, %eax	/* lofault value */
	ALTENTRY(do_copy_fault_nta)
	pushl	%ebp
	movl	%esp, %ebp		/* setup stack frame */
	pushl	%esi
	pushl	%edi

	movl	%gs:CPU_THREAD, %edx	
	movl	T_LOFAULT(%edx), %edi
	pushl	%edi			/* save the current lofault */
	movl	%eax, T_LOFAULT(%edx)	/* new lofault */

	/* COPY_LOOP_BODY needs to use %esi */
	movl	ARG_COUNT(%ebp), %ecx
	movl	ARG_FROM(%ebp), %edi
	movl	ARG_TO(%ebp), %eax
	COPY_LOOP_INIT(%edi, %eax, %ecx)
1:	COPY_LOOP_BODY(%edi, %eax, %ecx)
	jnz	1b
	mfence

	xorl	%eax, %eax
_kcopy_nta_copyerr:
	popl	%ecx
	popl	%edi
	movl	%ecx, T_LOFAULT(%edx)	/* restore the original lofault */
	popl	%esi
	leave
	ret
	SET_SIZE(do_copy_fault_nta)
	SET_SIZE(kcopy_nta)

#undef	ARG_FROM
#undef	ARG_TO
#undef	ARG_COUNT

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

/* ARGSUSED */
void
bcopy(const void *from, void *to, size_t count)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(bcopy)
#ifdef DEBUG
	orq	%rdx, %rdx		/* %rdx = count */
	jz	1f
	cmpq	postbootkernelbase(%rip), %rdi		/* %rdi = from */
	jb	0f
	cmpq	postbootkernelbase(%rip), %rsi		/* %rsi = to */		
	jnb	1f
0:	leaq	.bcopy_panic_msg(%rip), %rdi
	jmp	call_panic		/* setup stack and call panic */
1:
#endif
do_copy:
	xchgq	%rdi, %rsi		/* %rsi = source, %rdi = destination */
	movq	%rdx, %rcx		/* %rcx = count */
	shrq	$3, %rcx		/* 8-byte word count */
	rep
	  smovq

	movq	%rdx, %rcx
	andq	$7, %rcx		/* bytes left over */
	rep
	  smovb
	ret

#ifdef DEBUG
	/*
	 * Setup frame on the run-time stack. The end of the input argument
	 * area must be aligned on a 16 byte boundary. The stack pointer %rsp,
	 * always points to the end of the latest allocated stack frame.
	 * panic(const char *format, ...) is a varargs function. When a
	 * function taking variable arguments is called, %rax must be set
	 * to eight times the number of floating point parameters passed
	 * to the function in SSE registers.
	 */
call_panic:
	pushq	%rbp			/* align stack properly */
	movq	%rsp, %rbp
	xorl	%eax, %eax		/* no variable arguments */
	call	panic			/* %rdi = format string */
#endif
	SET_SIZE(bcopy)

#elif defined(__i386)

#define	ARG_FROM	4
#define	ARG_TO		8
#define	ARG_COUNT	12

	ENTRY(bcopy)
#ifdef DEBUG
	movl	ARG_COUNT(%esp), %eax
	orl	%eax, %eax
	jz	1f
	movl	postbootkernelbase, %eax
	cmpl	%eax, ARG_FROM(%esp)
	jb	0f
	cmpl	%eax, ARG_TO(%esp)
	jnb	1f
0:	pushl	%ebp
	movl	%esp, %ebp
	pushl	$.bcopy_panic_msg
	call	panic
1:
#endif
do_copy:
	movl	%esi, %eax		/* save registers */
	movl	%edi, %edx
	movl	ARG_COUNT(%esp), %ecx
	movl	ARG_FROM(%esp), %esi
	movl	ARG_TO(%esp), %edi

	shrl	$2, %ecx		/* word count */
	rep
	  smovl
	movl	ARG_COUNT(%esp), %ecx
	andl	$3, %ecx		/* bytes left over */
	rep
	  smovb
	movl	%eax, %esi		/* restore registers */
	movl	%edx, %edi
	ret
	SET_SIZE(bcopy)

#undef	ARG_COUNT
#undef	ARG_FROM
#undef	ARG_TO

#endif	/* __i386 */
#endif	/* __lint */


/*
 * Zero a block of storage, returning an error code if we
 * take a kernel pagefault which cannot be resolved.
 * Returns errno value on pagefault error, 0 if all ok
 */

#if defined(__lint)

/* ARGSUSED */
int
kzero(void *addr, size_t count)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(kzero)
#ifdef DEBUG
        cmpq	postbootkernelbase(%rip), %rdi	/* %rdi = addr */
        jnb	0f
        leaq	.kzero_panic_msg(%rip), %rdi
	jmp	call_panic		/* setup stack and call panic */
0:
#endif
	/*
	 * pass lofault value as 3rd argument to do_zero_fault
	 */
	leaq	_kzeroerr(%rip), %rdx

do_zero_fault:
	movq	%gs:CPU_THREAD, %r9	/* %r9 = thread addr */
	movq	T_LOFAULT(%r9), %r11	/* save the current lofault */
	movq	%rdx, T_LOFAULT(%r9)	/* new lofault */
	
	movq	%rsi, %rcx		/* get size in bytes */
	shrq	$3, %rcx		/* count of 8-byte words to zero */
	xorl	%eax, %eax		/* clear %rax; used in sstoq / sstob */
	rep
	  sstoq				/* %rcx = words to clear (%rax=0) */

	movq	%rsi, %rcx
	andq	$7, %rcx		/* bytes left over */
	rep
	  sstob				/* %rcx = residual bytes to clear */
	
	/*
	 * A fault during do_zero_fault is indicated through an errno value
	 * in %rax when we iretq to here.
	 */
_kzeroerr:
	movq	%r11, T_LOFAULT(%r9)	/* restore the original lofault */
	ret
	SET_SIZE(kzero)

#elif defined(__i386)

#define	ARG_ADDR	8
#define	ARG_COUNT	12

	ENTRY(kzero)
#ifdef DEBUG
	pushl	%ebp
	movl	%esp, %ebp
	movl	postbootkernelbase, %eax
        cmpl	%eax, ARG_ADDR(%ebp)
        jnb	0f
        pushl   $.kzero_panic_msg
        call    panic
0:	popl	%ebp
#endif
	lea	_kzeroerr, %eax		/* kzeroerr is lofault value */

do_zero_fault:
	pushl	%ebp			/* save stack base */
	movl	%esp, %ebp		/* set new stack base */
	pushl	%edi			/* save %edi */

	mov	%gs:CPU_THREAD, %edx	
	movl	T_LOFAULT(%edx), %edi
	pushl	%edi			/* save the current lofault */
	movl	%eax, T_LOFAULT(%edx)	/* new lofault */

	movl	ARG_COUNT(%ebp), %ecx	/* get size in bytes */
	movl	ARG_ADDR(%ebp), %edi	/* %edi <- address of bytes to clear */
	shrl	$2, %ecx		/* Count of double words to zero */
	xorl	%eax, %eax		/* sstol val */
	rep
	  sstol			/* %ecx contains words to clear (%eax=0) */

	movl	ARG_COUNT(%ebp), %ecx	/* get size in bytes */
	andl	$3, %ecx		/* do mod 4 */
	rep
	  sstob			/* %ecx contains residual bytes to clear */

	/*
	 * A fault during do_zero_fault is indicated through an errno value
	 * in %eax when we iret to here.
	 */
_kzeroerr:
	popl	%edi
	movl	%edi, T_LOFAULT(%edx)	/* restore the original lofault */
	popl	%edi
	popl	%ebp
	ret
	SET_SIZE(kzero)

#undef	ARG_ADDR
#undef	ARG_COUNT

#endif	/* __i386 */
#endif	/* __lint */

/*
 * Zero a block of storage.
 */

#if defined(__lint)

/* ARGSUSED */
void
bzero(void *addr, size_t count)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(bzero)
#ifdef DEBUG
	cmpq	postbootkernelbase(%rip), %rdi	/* %rdi = addr */
	jnb	0f
	leaq	.bzero_panic_msg(%rip), %rdi
	jmp	call_panic		/* setup stack and call panic */
0:
#endif
do_zero:
	movq	%rsi, %rcx		/* get size in bytes */
	shrq	$3, %rcx		/* count of 8-byte words to zero */
	xorl	%eax, %eax		/* clear %rax; used in sstoq / sstob */
	rep
	  sstoq				/* %rcx = words to clear (%rax=0) */

	movq	%rsi, %rcx
	andq	$7, %rcx		/* bytes left over */
	rep
	  sstob				/* %rcx = residual bytes to clear */
	ret
	SET_SIZE(bzero)

#elif defined(__i386)

#define	ARG_ADDR	4
#define	ARG_COUNT	8

	ENTRY(bzero)
#ifdef DEBUG
	movl	postbootkernelbase, %eax
	cmpl	%eax, ARG_ADDR(%esp)
	jnb	0f
	pushl	%ebp
	movl	%esp, %ebp
	pushl	$.bzero_panic_msg
	call	panic
0:
#endif
do_zero:
	movl	%edi, %edx
	movl	ARG_COUNT(%esp), %ecx
	movl	ARG_ADDR(%esp), %edi
	shrl	$2, %ecx
	xorl	%eax, %eax
	rep
	  sstol
	movl	ARG_COUNT(%esp), %ecx
	andl	$3, %ecx
	rep
	  sstob
	movl	%edx, %edi
	ret
	SET_SIZE(bzero)

#undef	ARG_ADDR
#undef	ARG_COUNT

#endif	/* __i386 */
#endif	/* __lint */

/*
 * Transfer data to and from user space -
 * Note that these routines can cause faults
 * It is assumed that the kernel has nothing at
 * less than KERNELBASE in the virtual address space.
 *
 * Note that copyin(9F) and copyout(9F) are part of the
 * DDI/DKI which specifies that they return '-1' on "errors."
 *
 * Sigh.
 *
 * So there's two extremely similar routines - xcopyin_nta() and
 * xcopyout_nta() which return the errno that we've faithfully computed.
 * This allows other callers (e.g. uiomove(9F)) to work correctly.
 * Given that these are used pretty heavily, we expand the calling
 * sequences inline for all flavours (rather than making wrappers).
 */

/*
 * Copy user data to kernel space.
 */

#if defined(__lint)

/* ARGSUSED */
int
copyin(const void *uaddr, void *kaddr, size_t count)
{ return (0); }

#else	/* lint */

#if defined(__amd64)

	ENTRY(copyin)
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$32, %rsp

	/*
	 * save args in case we trap and need to rerun as a copyop
	 */
	movq	%rdi, (%rsp)
	movq	%rsi, 0x8(%rsp)
	movq	%rdx, 0x10(%rsp)

	movq	kernelbase(%rip), %rax
#ifdef DEBUG
	cmpq	%rax, %rsi		/* %rsi = kaddr */
	jnb	1f
	leaq	.copyin_panic_msg(%rip), %rdi
	xorl	%eax, %eax
	call	panic
1:
#endif
	/*
	 * pass lofault value as 4th argument to do_copy_fault
	 */
	leaq	_copyin_err(%rip), %rcx

	movq	%gs:CPU_THREAD, %r9
	cmpq	%rax, %rdi		/* test uaddr < kernelbase */
	jb	do_copy_fault
	jmp	3f

_copyin_err:
	movq	%r11, T_LOFAULT(%r9)	/* restore original lofault */	
3:
	movq	T_COPYOPS(%r9), %rax
	cmpq	$0, %rax
	jz	2f
	/*
	 * reload args for the copyop
	 */
	movq	(%rsp), %rdi
	movq	0x8(%rsp), %rsi
	movq	0x10(%rsp), %rdx
	leave
	jmp	*CP_COPYIN(%rax)

2:	movl	$-1, %eax	
	leave
	ret
	SET_SIZE(copyin)

#elif defined(__i386)

#define	ARG_UADDR	4
#define	ARG_KADDR	8

	ENTRY(copyin)
	movl	kernelbase, %ecx
#ifdef DEBUG
	cmpl	%ecx, ARG_KADDR(%esp)
	jnb	1f
	pushl	%ebp
	movl	%esp, %ebp
	pushl	$.copyin_panic_msg
	call	panic
1:
#endif
	lea	_copyin_err, %eax

	movl	%gs:CPU_THREAD, %edx
	cmpl	%ecx, ARG_UADDR(%esp)	/* test uaddr < kernelbase */
	jb	do_copy_fault
	jmp	3f

_copyin_err:
	popl	%ecx
	popl	%edi
	movl	%ecx, T_LOFAULT(%edx)	/* restore original lofault */
	popl	%esi
	popl	%ebp
3:
	movl	T_COPYOPS(%edx), %eax
	cmpl	$0, %eax
	jz	2f
	jmp	*CP_COPYIN(%eax)

2:	movl	$-1, %eax
	ret
	SET_SIZE(copyin)

#undef	ARG_UADDR
#undef	ARG_KADDR

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

/* ARGSUSED */
int
xcopyin_nta(const void *uaddr, void *kaddr, size_t count, int copy_cached)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(xcopyin_nta)
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$32, %rsp

	/*
	 * save args in case we trap and need to rerun as a copyop
	 * %rcx is consumed in this routine so we don't need to save
	 * it.
	 */
	movq	%rdi, (%rsp)
	movq	%rsi, 0x8(%rsp)
	movq	%rdx, 0x10(%rsp)

	movq	kernelbase(%rip), %rax
#ifdef DEBUG
	cmpq	%rax, %rsi		/* %rsi = kaddr */
	jnb	1f
	leaq	.xcopyin_panic_msg(%rip), %rdi
	xorl	%eax, %eax
	call	panic
1:
#endif
	movq	%gs:CPU_THREAD, %r9
	cmpq	%rax, %rdi		/* test uaddr < kernelbase */
	jae	4f
	cmpq	$0, %rcx		/* No non-temporal access? */
	/*
	 * pass lofault value as 4th argument to do_copy_fault
	 */
	leaq	_xcopyin_err(%rip), %rcx	/* doesn't set rflags */
	jnz	do_copy_fault		/* use regular access */
	/*
	 * Make sure cnt is >= XCOPY_MIN_SIZE bytes
	 */
	cmpq	$XCOPY_MIN_SIZE, %rdx
	jb	do_copy_fault
	
	/*
	 * Make sure src and dst are NTA_ALIGN_SIZE aligned,
	 * count is COUNT_ALIGN_SIZE aligned.
	 */
	movq	%rdi, %r10
	orq	%rsi, %r10
	andq	$NTA_ALIGN_MASK, %r10
	orq	%rdx, %r10
	andq	$COUNT_ALIGN_MASK, %r10
	jnz	do_copy_fault
	jmp	do_copy_fault_nta	/* use non-temporal access */
	
4:
	movl	$EFAULT, %eax
	jmp	3f

	/*
	 * A fault during do_copy_fault or do_copy_fault_nta is
	 * indicated through an errno value in %rax and we iret from the
	 * trap handler to here.
	 */
_xcopyin_err:
	movq	%r11, T_LOFAULT(%r9)	/* restore original lofault */
3:
	movq	T_COPYOPS(%r9), %r8
	cmpq	$0, %r8
	jz	2f

	/*
	 * reload args for the copyop
	 */
	movq	(%rsp), %rdi
	movq	0x8(%rsp), %rsi
	movq	0x10(%rsp), %rdx
	leave
	jmp	*CP_XCOPYIN(%r8)

2:	leave
	ret
	SET_SIZE(xcopyin_nta)

#elif defined(__i386)

#define	ARG_UADDR	4
#define	ARG_KADDR	8
#define	ARG_COUNT	12
#define	ARG_CACHED	16

	.globl	use_sse_copy

	ENTRY(xcopyin_nta)
	movl	kernelbase, %ecx
	lea	_xcopyin_err, %eax
	movl	%gs:CPU_THREAD, %edx
	cmpl	%ecx, ARG_UADDR(%esp)	/* test uaddr < kernelbase */
	jae	4f

	cmpl	$0, use_sse_copy	/* no sse support */
	jz	do_copy_fault

	cmpl	$0, ARG_CACHED(%esp)	/* copy_cached hint set? */
	jnz	do_copy_fault

	/*
	 * Make sure cnt is >= XCOPY_MIN_SIZE bytes
	 */
	cmpl	$XCOPY_MIN_SIZE, ARG_COUNT(%esp)
	jb	do_copy_fault
	
	/*
	 * Make sure src and dst are NTA_ALIGN_SIZE aligned,
	 * count is COUNT_ALIGN_SIZE aligned.
	 */
	movl	ARG_UADDR(%esp), %ecx
	orl	ARG_KADDR(%esp), %ecx
	andl	$NTA_ALIGN_MASK, %ecx
	orl	ARG_COUNT(%esp), %ecx
	andl	$COUNT_ALIGN_MASK, %ecx
	jnz	do_copy_fault

	jmp	do_copy_fault_nta	/* use regular access */

4:
	movl	$EFAULT, %eax
	jmp	3f

	/*
	 * A fault during do_copy_fault or do_copy_fault_nta is
	 * indicated through an errno value in %eax and we iret from the
	 * trap handler to here.
	 */
_xcopyin_err:
	popl	%ecx
	popl	%edi
	movl	%ecx, T_LOFAULT(%edx)	/* restore original lofault */
	popl	%esi
	popl	%ebp
3:
	cmpl	$0, T_COPYOPS(%edx)
	jz	2f
	movl	T_COPYOPS(%edx), %eax
	jmp	*CP_XCOPYIN(%eax)

2:	rep; 	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	SET_SIZE(xcopyin_nta)

#undef	ARG_UADDR
#undef	ARG_KADDR
#undef	ARG_COUNT
#undef	ARG_CACHED

#endif	/* __i386 */
#endif	/* __lint */

/*
 * Copy kernel data to user space.
 */

#if defined(__lint)

/* ARGSUSED */
int
copyout(const void *kaddr, void *uaddr, size_t count)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(copyout)
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$32, %rsp

	/*
	 * save args in case we trap and need to rerun as a copyop
	 */
	movq	%rdi, (%rsp)
	movq	%rsi, 0x8(%rsp)
	movq	%rdx, 0x10(%rsp)

	movq	kernelbase(%rip), %rax
#ifdef DEBUG
	cmpq	%rax, %rdi		/* %rdi = kaddr */
	jnb	1f
	leaq	.copyout_panic_msg(%rip), %rdi
	xorl	%eax, %eax
	call	panic
1:
#endif
	/*
	 * pass lofault value as 4th argument to do_copy_fault
	 */
	leaq	_copyout_err(%rip), %rcx

	movq	%gs:CPU_THREAD, %r9
	cmpq	%rax, %rsi		/* test uaddr < kernelbase */
	jb	do_copy_fault
	jmp	3f

_copyout_err:
	movq	%r11, T_LOFAULT(%r9)	/* restore original lofault */
3:
	movq	T_COPYOPS(%r9), %rax
	cmpq	$0, %rax
	jz	2f

	/*
	 * reload args for the copyop
	 */
	movq	(%rsp), %rdi
	movq	0x8(%rsp), %rsi
	movq	0x10(%rsp), %rdx
	leave
	jmp	*CP_COPYOUT(%rax)

2:	movl	$-1, %eax
	leave
	ret
	SET_SIZE(copyout)

#elif defined(__i386)

#define	ARG_KADDR	4
#define	ARG_UADDR	8

	ENTRY(copyout)
	movl	kernelbase, %ecx
#ifdef DEBUG
	cmpl	%ecx, ARG_KADDR(%esp)
	jnb	1f
	pushl	%ebp
	movl	%esp, %ebp
	pushl	$.copyout_panic_msg
	call	panic
1:
#endif
	lea	_copyout_err, %eax
	movl	%gs:CPU_THREAD, %edx
	cmpl	%ecx, ARG_UADDR(%esp)	/* test uaddr < kernelbase */
	jb	do_copy_fault
	jmp	3f
	
_copyout_err:
	popl	%ecx
	popl	%edi
	movl	%ecx, T_LOFAULT(%edx)	/* restore original lofault */
	popl	%esi
	popl	%ebp
3:
	movl	T_COPYOPS(%edx), %eax
	cmpl	$0, %eax
	jz	2f
	jmp	*CP_COPYOUT(%eax)

2:	movl	$-1, %eax
	ret
	SET_SIZE(copyout)

#undef	ARG_UADDR
#undef	ARG_KADDR

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

/* ARGSUSED */
int
xcopyout_nta(const void *kaddr, void *uaddr, size_t count, int copy_cached)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(xcopyout_nta)
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$32, %rsp

	/*
	 * save args in case we trap and need to rerun as a copyop
	 */
	movq	%rdi, (%rsp)
	movq	%rsi, 0x8(%rsp)
	movq	%rdx, 0x10(%rsp)

	movq	kernelbase(%rip), %rax
#ifdef DEBUG
	cmpq	%rax, %rdi		/* %rdi = kaddr */
	jnb	1f
	leaq	.xcopyout_panic_msg(%rip), %rdi
	xorl	%eax, %eax
	call	panic
1:
#endif
	movq	%gs:CPU_THREAD, %r9
	cmpq	%rax, %rsi		/* test uaddr < kernelbase */
	jae	4f

	cmpq	$0, %rcx		/* No non-temporal access? */
	/*
	 * pass lofault value as 4th argument to do_copy_fault
	 */
	leaq	_xcopyout_err(%rip), %rcx
	jnz	do_copy_fault
	/*
	 * Make sure cnt is >= XCOPY_MIN_SIZE bytes
	 */
	cmpq	$XCOPY_MIN_SIZE, %rdx
	jb	do_copy_fault
	
	/*
	 * Make sure src and dst are NTA_ALIGN_SIZE aligned,
	 * count is COUNT_ALIGN_SIZE aligned.
	 */
	movq	%rdi, %r10
	orq	%rsi, %r10
	andq	$NTA_ALIGN_MASK, %r10
	orq	%rdx, %r10
	andq	$COUNT_ALIGN_MASK, %r10
	jnz	do_copy_fault
	jmp	do_copy_fault_nta

4:
	movl	$EFAULT, %eax
	jmp	3f

	/*
	 * A fault during do_copy_fault or do_copy_fault_nta is
	 * indicated through an errno value in %rax and we iret from the
	 * trap handler to here.
	 */
_xcopyout_err:
	movq	%r11, T_LOFAULT(%r9)	/* restore original lofault */
3:
	movq	T_COPYOPS(%r9), %r8
	cmpq	$0, %r8
	jz	2f

	/*
	 * reload args for the copyop
	 */
	movq	(%rsp), %rdi
	movq	0x8(%rsp), %rsi
	movq	0x10(%rsp), %rdx
	leave
	jmp	*CP_XCOPYOUT(%r8)

2:	leave
	ret
	SET_SIZE(xcopyout_nta)

#elif defined(__i386)

#define	ARG_KADDR	4
#define	ARG_UADDR	8
#define	ARG_COUNT	12
#define	ARG_CACHED	16

	ENTRY(xcopyout_nta)
	movl	kernelbase, %ecx
	lea	_xcopyout_err, %eax
	movl	%gs:CPU_THREAD, %edx
	cmpl	%ecx, ARG_UADDR(%esp)	/* test uaddr < kernelbase */
	jae	4f

	cmpl	$0, use_sse_copy	/* no sse support */
	jz	do_copy_fault

	cmpl	$0, ARG_CACHED(%esp)	/* copy_cached hint set? */
	jnz	do_copy_fault

	/*
	 * Make sure cnt is >= XCOPY_MIN_SIZE bytes
	 */
	cmpl	$XCOPY_MIN_SIZE, %edx
	jb	do_copy_fault
	
	/*
	 * Make sure src and dst are NTA_ALIGN_SIZE aligned,
	 * count is COUNT_ALIGN_SIZE aligned.
	 */
	movl	ARG_UADDR(%esp), %ecx
	orl	ARG_KADDR(%esp), %ecx
	andl	$NTA_ALIGN_MASK, %ecx
	orl	ARG_COUNT(%esp), %ecx
	andl	$COUNT_ALIGN_MASK, %ecx
	jnz	do_copy_fault
	jmp	do_copy_fault_nta

4:
	movl	$EFAULT, %eax
	jmp	3f

	/*
	 * A fault during do_copy_fault or do_copy_fault_nta is
	 * indicated through an errno value in %eax and we iret from the
	 * trap handler to here.
	 */
_xcopyout_err:
	/ restore the original lofault
	popl	%ecx
	popl	%edi
	movl	%ecx, T_LOFAULT(%edx)	/ original lofault
	popl	%esi
	popl	%ebp
3:
	cmpl	$0, T_COPYOPS(%edx)
	jz	2f
	movl	T_COPYOPS(%edx), %eax
	jmp	*CP_XCOPYOUT(%eax)

2:	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	SET_SIZE(xcopyout_nta)

#undef	ARG_UADDR
#undef	ARG_KADDR
#undef	ARG_COUNT
#undef	ARG_CACHED

#endif	/* __i386 */
#endif	/* __lint */

/*
 * Copy a null terminated string from one point to another in
 * the kernel address space.
 */

#if defined(__lint)

/* ARGSUSED */
int
copystr(const char *from, char *to, size_t maxlength, size_t *lencopied)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(copystr)
	pushq	%rbp
	movq	%rsp, %rbp
#ifdef DEBUG
	movq	kernelbase(%rip), %rax
	cmpq	%rax, %rdi		/* %rdi = from */
	jb	0f
	cmpq	%rax, %rsi		/* %rsi = to */
	jnb	1f
0:	leaq	.copystr_panic_msg(%rip), %rdi
	xorl	%eax, %eax
	call	panic
1:
#endif
	movq	%gs:CPU_THREAD, %r9
	movq	T_LOFAULT(%r9), %r8	/* pass current lofault value as */
					/* 5th argument to do_copystr */
do_copystr:
	movq	%gs:CPU_THREAD, %r9	/* %r9 = thread addr */
	movq    T_LOFAULT(%r9), %r11	/* save the current lofault */
	movq	%r8, T_LOFAULT(%r9)	/* new lofault */

	movq	%rdx, %r8		/* save maxlength */

	cmpq	$0, %rdx		/* %rdx = maxlength */
	je	copystr_enametoolong	/* maxlength == 0 */

copystr_loop:
	decq	%r8
	movb	(%rdi), %al
	incq	%rdi
	movb	%al, (%rsi)
	incq	%rsi
	cmpb	$0, %al
	je	copystr_null		/* null char */
	cmpq	$0, %r8
	jne	copystr_loop

copystr_enametoolong:
	movl	$ENAMETOOLONG, %eax
	jmp	copystr_out

copystr_null:
	xorl	%eax, %eax		/* no error */

copystr_out:
	cmpq	$0, %rcx		/* want length? */
	je	copystr_done		/* no */
	subq	%r8, %rdx		/* compute length and store it */
	movq	%rdx, (%rcx)

copystr_done:
	movq	%r11, T_LOFAULT(%r9)	/* restore the original lofault */
	leave
	ret
	SET_SIZE(copystr)

#elif defined(__i386)

#define	ARG_FROM	8
#define	ARG_TO		12
#define	ARG_MAXLEN	16
#define	ARG_LENCOPIED	20

	ENTRY(copystr)
#ifdef DEBUG
	pushl	%ebp
	movl	%esp, %ebp
	movl	kernelbase, %eax
	cmpl	%eax, ARG_FROM(%esp)
	jb	0f
	cmpl	%eax, ARG_TO(%esp)
	jnb	1f
0:	pushl	$.copystr_panic_msg
	call	panic
1:	popl	%ebp
#endif
	/* get the current lofault address */
	movl	%gs:CPU_THREAD, %eax
	movl	T_LOFAULT(%eax), %eax
do_copystr:
	pushl	%ebp			/* setup stack frame */
	movl	%esp, %ebp
	pushl	%ebx			/* save registers */
	pushl	%edi

	movl	%gs:CPU_THREAD, %ebx	
	movl	T_LOFAULT(%ebx), %edi
	pushl	%edi			/* save the current lofault */
	movl	%eax, T_LOFAULT(%ebx)	/* new lofault */

	movl	ARG_MAXLEN(%ebp), %ecx
	cmpl	$0, %ecx
	je	copystr_enametoolong	/* maxlength == 0 */

	movl	ARG_FROM(%ebp), %ebx	/* source address */
	movl	ARG_TO(%ebp), %edx	/* destination address */

copystr_loop:
	decl	%ecx
	movb	(%ebx), %al
	incl	%ebx	
	movb	%al, (%edx)
	incl	%edx
	cmpb	$0, %al
	je	copystr_null		/* null char */
	cmpl	$0, %ecx
	jne	copystr_loop

copystr_enametoolong:
	movl	$ENAMETOOLONG, %eax
	jmp	copystr_out

copystr_null:
	xorl	%eax, %eax		/* no error */

copystr_out:
	cmpl	$0, ARG_LENCOPIED(%ebp)	/* want length? */
	je	copystr_done		/* no */
	movl	ARG_MAXLEN(%ebp), %edx
	subl	%ecx, %edx		/* compute length and store it */
	movl	ARG_LENCOPIED(%ebp), %ecx
	movl	%edx, (%ecx)

copystr_done:
	popl	%edi
	movl	%gs:CPU_THREAD, %ebx	
	movl	%edi, T_LOFAULT(%ebx)	/* restore the original lofault */

	popl	%edi
	popl	%ebx
	popl	%ebp
	ret	
	SET_SIZE(copystr)

#undef	ARG_FROM
#undef	ARG_TO
#undef	ARG_MAXLEN
#undef	ARG_LENCOPIED

#endif	/* __i386 */
#endif	/* __lint */

/*
 * Copy a null terminated string from the user address space into
 * the kernel address space.
 */

#if defined(__lint)

/* ARGSUSED */
int
copyinstr(const char *uaddr, char *kaddr, size_t maxlength,
    size_t *lencopied)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(copyinstr)
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$32, %rsp

	/*
	 * save args in case we trap and need to rerun as a copyop
	 */
	movq	%rdi, (%rsp)
	movq	%rsi, 0x8(%rsp)
	movq	%rdx, 0x10(%rsp)
	movq	%rcx, 0x18(%rsp)

	movq	kernelbase(%rip), %rax
#ifdef DEBUG
	cmpq	%rax, %rsi		/* %rsi = kaddr */
	jnb	1f
	leaq	.copyinstr_panic_msg(%rip), %rdi
	xorl	%eax, %eax
	call	panic
1:
#endif
	/*
	 * pass lofault value as 5th argument to do_copystr
	 */
	leaq	_copyinstr_error(%rip), %r8

	cmpq	%rax, %rdi		/* test uaddr < kernelbase */
	jb	do_copystr
	movq	%gs:CPU_THREAD, %r9
	jmp	3f

_copyinstr_error:
	movq	%r11, T_LOFAULT(%r9)	/* restore original lofault */
3:
	movq	T_COPYOPS(%r9), %rax
	cmpq	$0, %rax
	jz	2f

	/*
	 * reload args for the copyop
	 */
	movq	(%rsp), %rdi
	movq	0x8(%rsp), %rsi
	movq	0x10(%rsp), %rdx
	movq	0x18(%rsp), %rcx
	leave
	jmp	*CP_COPYINSTR(%rax)
	
2:	movl	$EFAULT, %eax		/* return EFAULT */
	leave
	ret
	SET_SIZE(copyinstr)

#elif defined(__i386)

#define	ARG_UADDR	4
#define	ARG_KADDR	8

	ENTRY(copyinstr)
	movl	kernelbase, %ecx
#ifdef DEBUG
	cmpl	%ecx, ARG_KADDR(%esp)
	jnb	1f
	pushl	%ebp
	movl	%esp, %ebp
	pushl	$.copyinstr_panic_msg
	call	panic
1:
#endif
	lea	_copyinstr_error, %eax
	cmpl	%ecx, ARG_UADDR(%esp)	/* test uaddr < kernelbase */
	jb	do_copystr
	movl	%gs:CPU_THREAD, %edx
	jmp	3f

_copyinstr_error:
	popl	%edi
	movl	%gs:CPU_THREAD, %edx	
	movl	%edi, T_LOFAULT(%edx)	/* original lofault */

	popl	%edi
	popl	%ebx
	popl	%ebp
3:
	movl	T_COPYOPS(%edx), %eax
	cmpl	$0, %eax
	jz	2f
	jmp	*CP_COPYINSTR(%eax)
	
2:	movl	$EFAULT, %eax		/* return EFAULT */
	ret
	SET_SIZE(copyinstr)

#undef	ARG_UADDR
#undef	ARG_KADDR

#endif	/* __i386 */
#endif	/* __lint */

/*
 * Copy a null terminated string from the kernel
 * address space to the user address space.
 */

#if defined(__lint)

/* ARGSUSED */
int
copyoutstr(const char *kaddr, char *uaddr, size_t maxlength,
    size_t *lencopied)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(copyoutstr)
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$32, %rsp

	/*
	 * save args in case we trap and need to rerun as a copyop
	 */
	movq	%rdi, (%rsp)
	movq	%rsi, 0x8(%rsp)
	movq	%rdx, 0x10(%rsp)
	movq	%rcx, 0x18(%rsp)

	movq	kernelbase(%rip), %rax
#ifdef DEBUG
	cmpq	%rax, %rdi		/* %rdi = kaddr */
	jnb	1f
	leaq	.copyoutstr_panic_msg(%rip), %rdi
	jmp	call_panic		/* setup stack and call panic */
1:
#endif
	/*
	 * pass lofault value as 5th argument to do_copystr
	 */
	leaq	_copyoutstr_error(%rip), %r8

	cmpq	%rax, %rsi		/* test uaddr < kernelbase */
	jb	do_copystr
	movq	%gs:CPU_THREAD, %r9
	jmp	3f

_copyoutstr_error:
	movq	%r11, T_LOFAULT(%r9)	/* restore the original lofault */
3:
	movq	T_COPYOPS(%r9), %rax
	cmpq	$0, %rax
	jz	2f

	/*
	 * reload args for the copyop
	 */
	movq	(%rsp), %rdi
	movq	0x8(%rsp), %rsi
	movq	0x10(%rsp), %rdx
	movq	0x18(%rsp), %rcx
	leave
	jmp	*CP_COPYOUTSTR(%rax)
	
2:	movl	$EFAULT, %eax		/* return EFAULT */
	leave
	ret
	SET_SIZE(copyoutstr)	
	
#elif defined(__i386)

#define	ARG_KADDR	4
#define	ARG_UADDR	8

	ENTRY(copyoutstr)
	movl	kernelbase, %ecx
#ifdef DEBUG
	cmpl	%ecx, ARG_KADDR(%esp)
	jnb	1f
	pushl	%ebp
	movl	%esp, %ebp
	pushl	$.copyoutstr_panic_msg
	call	panic
1:
#endif
	lea	_copyoutstr_error, %eax
	cmpl	%ecx, ARG_UADDR(%esp)	/* test uaddr < kernelbase */
	jb	do_copystr
	movl	%gs:CPU_THREAD, %edx
	jmp	3f

_copyoutstr_error:
	popl	%edi
	movl	%gs:CPU_THREAD, %edx	
	movl	%edi, T_LOFAULT(%edx)	/* restore the original lofault */

	popl	%edi
	popl	%ebx
	popl	%ebp
3:
	movl	T_COPYOPS(%edx), %eax
	cmpl	$0, %eax
	jz	2f
	jmp	*CP_COPYOUTSTR(%eax)

2:	movl	$EFAULT, %eax		/* return EFAULT */
	ret
	SET_SIZE(copyoutstr)
	
#undef	ARG_KADDR
#undef	ARG_UADDR

#endif	/* __i386 */
#endif	/* __lint */

/*
 * Since all of the fuword() variants are so similar, we have a macro to spit
 * them out.  This allows us to create DTrace-unobservable functions easily.
 */
	
#if defined(__lint)

#if defined(__amd64)

/* ARGSUSED */
int
fuword64(const void *addr, uint64_t *dst)
{ return (0); }

#endif

/* ARGSUSED */
int
fuword32(const void *addr, uint32_t *dst)
{ return (0); }

/* ARGSUSED */
int
fuword16(const void *addr, uint16_t *dst)
{ return (0); }

/* ARGSUSED */
int
fuword8(const void *addr, uint8_t *dst)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

/*
 * (Note that we don't save and reload the arguments here
 * because their values are not altered in the copy path)
 */

#define	FUWORD(NAME, INSTR, REG, COPYOP)	\
	ENTRY(NAME)				\
	movq	%gs:CPU_THREAD, %r9;		\
	cmpq	kernelbase(%rip), %rdi;		\
	jae	1f;				\
	leaq	_flt_/**/NAME, %rdx;		\
	movq	%rdx, T_LOFAULT(%r9);		\
	INSTR	(%rdi), REG;			\
	movq	$0, T_LOFAULT(%r9);		\
	INSTR	REG, (%rsi);			\
	xorl	%eax, %eax;			\
	ret;					\
_flt_/**/NAME:					\
	movq	$0, T_LOFAULT(%r9);		\
1:						\
	movq	T_COPYOPS(%r9), %rax;		\
	cmpq	$0, %rax;			\
	jz	2f;				\
	jmp	*COPYOP(%rax);			\
2:						\
	movl	$-1, %eax;			\
	ret;					\
	SET_SIZE(NAME)
	
	FUWORD(fuword64, movq, %rax, CP_FUWORD64)
	FUWORD(fuword32, movl, %eax, CP_FUWORD32)
	FUWORD(fuword16, movw, %ax, CP_FUWORD16)
	FUWORD(fuword8, movb, %al, CP_FUWORD8)

#elif defined(__i386)

#define	FUWORD(NAME, INSTR, REG, COPYOP)	\
	ENTRY(NAME)				\
	movl	%gs:CPU_THREAD, %ecx;		\
	movl	kernelbase, %eax;		\
	cmpl	%eax, 4(%esp);			\
	jae	1f;				\
	lea	_flt_/**/NAME, %edx;		\
	movl	%edx, T_LOFAULT(%ecx);		\
	movl	4(%esp), %eax;			\
	movl	8(%esp), %edx;			\
	INSTR	(%eax), REG;			\
	movl	$0, T_LOFAULT(%ecx);		\
	INSTR	REG, (%edx);			\
	xorl	%eax, %eax;			\
	ret;					\
_flt_/**/NAME:					\
	movl	$0, T_LOFAULT(%ecx);		\
1:						\
	movl	T_COPYOPS(%ecx), %eax;		\
	cmpl	$0, %eax;			\
	jz	2f;				\
	jmp	*COPYOP(%eax);			\
2:						\
	movl	$-1, %eax;			\
	ret;					\
	SET_SIZE(NAME)

	FUWORD(fuword32, movl, %eax, CP_FUWORD32)
	FUWORD(fuword16, movw, %ax, CP_FUWORD16)
	FUWORD(fuword8, movb, %al, CP_FUWORD8)

#endif	/* __i386 */

#undef	FUWORD

#endif	/* __lint */

/*
 * Set user word.
 */

#if defined(__lint)

#if defined(__amd64)

/* ARGSUSED */
int
suword64(void *addr, uint64_t value)
{ return (0); }

#endif

/* ARGSUSED */
int
suword32(void *addr, uint32_t value)
{ return (0); }

/* ARGSUSED */
int
suword16(void *addr, uint16_t value)
{ return (0); }

/* ARGSUSED */
int
suword8(void *addr, uint8_t value)
{ return (0); }

#else	/* lint */

#if defined(__amd64)

/*
 * (Note that we don't save and reload the arguments here
 * because their values are not altered in the copy path)
 */

#define	SUWORD(NAME, INSTR, REG, COPYOP)	\
	ENTRY(NAME)				\
	movq	%gs:CPU_THREAD, %r9;		\
	cmpq	kernelbase(%rip), %rdi;		\
	jae	1f;				\
	leaq	_flt_/**/NAME, %rdx;		\
	movq	%rdx, T_LOFAULT(%r9);		\
	INSTR	REG, (%rdi);			\
	movq	$0, T_LOFAULT(%r9);		\
	xorl	%eax, %eax;			\
	ret;					\
_flt_/**/NAME:					\
	movq	$0, T_LOFAULT(%r9);		\
1:						\
	movq	T_COPYOPS(%r9), %rax;		\
	cmpq	$0, %rax;			\
	jz	3f;				\
	jmp	*COPYOP(%rax);			\
3:						\
	movl	$-1, %eax;			\
	ret;					\
	SET_SIZE(NAME)

	SUWORD(suword64, movq, %rsi, CP_SUWORD64)
	SUWORD(suword32, movl, %esi, CP_SUWORD32)
	SUWORD(suword16, movw, %si, CP_SUWORD16)
	SUWORD(suword8, movb, %sil, CP_SUWORD8)

#elif defined(__i386)

#define	SUWORD(NAME, INSTR, REG, COPYOP)	\
	ENTRY(NAME)				\
	movl	%gs:CPU_THREAD, %ecx;		\
	movl	kernelbase, %eax;		\
	cmpl	%eax, 4(%esp);			\
	jae	1f;				\
	lea	_flt_/**/NAME, %edx;		\
	movl	%edx, T_LOFAULT(%ecx);		\
	movl	4(%esp), %eax;			\
	movl	8(%esp), %edx;			\
	INSTR	REG, (%eax);			\
	movl	$0, T_LOFAULT(%ecx);		\
	xorl	%eax, %eax;			\
	ret;					\
_flt_/**/NAME:					\
	movl	$0, T_LOFAULT(%ecx);		\
1:						\
	movl	T_COPYOPS(%ecx), %eax;		\
	cmpl	$0, %eax;			\
	jz	3f;				\
	movl	COPYOP(%eax), %ecx;		\
	jmp	*%ecx;				\
3:						\
	movl	$-1, %eax;			\
	ret;					\
	SET_SIZE(NAME)

	SUWORD(suword32, movl, %edx, CP_SUWORD32)
	SUWORD(suword16, movw, %dx, CP_SUWORD16)
	SUWORD(suword8, movb, %dl, CP_SUWORD8)

#endif	/* __i386 */

#undef	SUWORD

#endif	/* __lint */

#if defined(__lint)

#if defined(__amd64)

/*ARGSUSED*/
void
fuword64_noerr(const void *addr, uint64_t *dst)
{}

#endif

/*ARGSUSED*/
void
fuword32_noerr(const void *addr, uint32_t *dst)
{}

/*ARGSUSED*/
void
fuword8_noerr(const void *addr, uint8_t *dst)
{}

/*ARGSUSED*/
void
fuword16_noerr(const void *addr, uint16_t *dst)
{}

#else   /* __lint */

#if defined(__amd64)

#define	FUWORD_NOERR(NAME, INSTR, REG)		\
	ENTRY(NAME)				\
	cmpq	kernelbase(%rip), %rdi;		\
	cmovnbq	kernelbase(%rip), %rdi;		\
	INSTR	(%rdi), REG;			\
	INSTR	REG, (%rsi);			\
	ret;					\
	SET_SIZE(NAME)

	FUWORD_NOERR(fuword64_noerr, movq, %rax)
	FUWORD_NOERR(fuword32_noerr, movl, %eax)
	FUWORD_NOERR(fuword16_noerr, movw, %ax)
	FUWORD_NOERR(fuword8_noerr, movb, %al)

#elif defined(__i386)

#define	FUWORD_NOERR(NAME, INSTR, REG)		\
	ENTRY(NAME)				\
	movl	4(%esp), %eax;			\
	cmpl	kernelbase, %eax;		\
	jb	1f;				\
	movl	kernelbase, %eax;		\
1:	movl	8(%esp), %edx;			\
	INSTR	(%eax), REG;			\
	INSTR	REG, (%edx);			\
	ret;					\
	SET_SIZE(NAME)

	FUWORD_NOERR(fuword32_noerr, movl, %ecx)
	FUWORD_NOERR(fuword16_noerr, movw, %cx)
	FUWORD_NOERR(fuword8_noerr, movb, %cl)

#endif	/* __i386 */

#undef	FUWORD_NOERR

#endif	/* __lint */

#if defined(__lint)

#if defined(__amd64)

/*ARGSUSED*/
void
suword64_noerr(void *addr, uint64_t value)
{}

#endif

/*ARGSUSED*/
void
suword32_noerr(void *addr, uint32_t value)
{}

/*ARGSUSED*/
void
suword16_noerr(void *addr, uint16_t value)
{}

/*ARGSUSED*/
void
suword8_noerr(void *addr, uint8_t value)
{}

#else	/* lint */

#if defined(__amd64)

#define	SUWORD_NOERR(NAME, INSTR, REG)		\
	ENTRY(NAME)				\
	cmpq	kernelbase(%rip), %rdi;		\
	cmovnbq	kernelbase(%rip), %rdi;		\
	INSTR	REG, (%rdi);			\
	ret;					\
	SET_SIZE(NAME)

	SUWORD_NOERR(suword64_noerr, movq, %rsi)
	SUWORD_NOERR(suword32_noerr, movl, %esi)
	SUWORD_NOERR(suword16_noerr, movw, %si)
	SUWORD_NOERR(suword8_noerr, movb, %sil)

#elif defined(__i386)

#define	SUWORD_NOERR(NAME, INSTR, REG)		\
	ENTRY(NAME)				\
	movl	4(%esp), %eax;			\
	cmpl	kernelbase, %eax;		\
	jb	1f;				\
	movl	kernelbase, %eax;		\
1:						\
	movl	8(%esp), %edx;			\
	INSTR	REG, (%eax);			\
	ret;					\
	SET_SIZE(NAME)

	SUWORD_NOERR(suword32_noerr, movl, %edx)
	SUWORD_NOERR(suword16_noerr, movw, %dx)
	SUWORD_NOERR(suword8_noerr, movb, %dl)

#endif	/* __i386 */

#undef	SUWORD_NOERR

#endif	/* lint */


#if defined(__lint)

/*ARGSUSED*/
int
subyte(void *addr, uchar_t value)
{ return (0); }

/*ARGSUSED*/
void
subyte_noerr(void *addr, uchar_t value)
{}

/*ARGSUSED*/
int
fulword(const void *addr, ulong_t *valuep)
{ return (0); }

/*ARGSUSED*/
void
fulword_noerr(const void *addr, ulong_t *valuep)
{}

/*ARGSUSED*/
int
sulword(void *addr, ulong_t valuep)
{ return (0); }

/*ARGSUSED*/
void
sulword_noerr(void *addr, ulong_t valuep)
{}

#else

	.weak	subyte
	subyte=suword8
	.weak	subyte_noerr
	subyte_noerr=suword8_noerr

#if defined(__amd64)

	.weak	fulword
	fulword=fuword64
	.weak	fulword_noerr
	fulword_noerr=fuword64_noerr
	.weak	sulword
	sulword=suword64
	.weak	sulword_noerr
	sulword_noerr=suword64_noerr

#elif defined(__i386)

	.weak	fulword
	fulword=fuword32
	.weak	fulword_noerr
	fulword_noerr=fuword32_noerr
	.weak	sulword
	sulword=suword32
	.weak	sulword_noerr
	sulword_noerr=suword32_noerr

#endif /* __i386 */

#endif /* __lint */

#if defined(__lint)

/*
 * Copy a block of storage - must not overlap (from + len <= to).
 * No fault handler installed (to be called under on_fault())
 */

/* ARGSUSED */
void
copyout_noerr(const void *kfrom, void *uto, size_t count)
{}

/* ARGSUSED */
void
copyin_noerr(const void *ufrom, void *kto, size_t count)
{}

/*
 * Zero a block of storage in user space
 */

/* ARGSUSED */
void
uzero(void *addr, size_t count)
{}

/*
 * copy a block of storage in user space
 */

/* ARGSUSED */
void
ucopy(const void *ufrom, void *uto, size_t ulength)
{}

/*
 * copy a string in user space
 */

/* ARGSUSED */
void
ucopystr(const char *ufrom, char *uto, size_t umaxlength, size_t *lencopied)
{}

#else /* __lint */

#if defined(__amd64)

	ENTRY(copyin_noerr)
	movq	kernelbase(%rip), %rax
#ifdef DEBUG
	cmpq	%rax, %rsi		/* %rsi = kto */
	jae	1f
	leaq	.cpyin_ne_pmsg(%rip), %rdi
	jmp	call_panic		/* setup stack and call panic */
1:
#endif
	cmpq	%rax, %rdi		/* ufrom < kernelbase */
	jb	do_copy
	movq	%rax, %rdi		/* force fault at kernelbase */
	jmp	do_copy
	SET_SIZE(copyin_noerr)

	ENTRY(copyout_noerr)
	movq	kernelbase(%rip), %rax
#ifdef DEBUG
	cmpq	%rax, %rdi		/* %rdi = kfrom */
	jae	1f
	leaq	.cpyout_ne_pmsg(%rip), %rdi
	jmp	call_panic		/* setup stack and call panic */
1:
#endif
	cmpq	%rax, %rsi		/* uto < kernelbase */
	jb	do_copy
	movq	%rax, %rsi		/* force fault at kernelbase */
	jmp	do_copy
	SET_SIZE(copyout_noerr)

	ENTRY(uzero)
	movq	kernelbase(%rip), %rax
	cmpq	%rax, %rdi
	jb	do_zero
	movq	%rax, %rdi	/* force fault at kernelbase */
	jmp	do_zero
	SET_SIZE(uzero)

	ENTRY(ucopy)
	movq	kernelbase(%rip), %rax
	cmpq	%rax, %rdi
	cmovaeq	%rax, %rdi	/* force fault at kernelbase */
	cmpq	%rax, %rsi
	cmovaeq	%rax, %rsi	/* force fault at kernelbase */
	jmp	do_copy
	SET_SIZE(ucopy)

	ENTRY(ucopystr)
	movq	kernelbase(%rip), %rax
	cmpq	%rax, %rdi
	cmovaeq	%rax, %rdi	/* force fault at kernelbase */
	cmpq	%rax, %rsi
	cmovaeq	%rax, %rsi	/* force fault at kernelbase */
	/* do_copystr expects lofault address in %r8 */
	movq	%gs:CPU_THREAD, %r8
	movq	T_LOFAULT(%r8), %r8
	jmp	do_copystr
	SET_SIZE(ucopystr)

#elif defined(__i386)

	ENTRY(copyin_noerr)
	movl	kernelbase, %eax
#ifdef DEBUG
	cmpl	%eax, 8(%esp)
	jae	1f
	pushl	$.cpyin_ne_pmsg
	call	panic
1:
#endif
	cmpl	%eax, 4(%esp)
	jb	do_copy
	movl	%eax, 4(%esp)	/* force fault at kernelbase */
	jmp	do_copy
	SET_SIZE(copyin_noerr)

	ENTRY(copyout_noerr)
	movl	kernelbase, %eax
#ifdef DEBUG
	cmpl	%eax, 4(%esp)
	jae	1f
	pushl	$.cpyout_ne_pmsg
	call	panic
1:
#endif
	cmpl	%eax, 8(%esp)
	jb	do_copy
	movl	%eax, 8(%esp)	/* force fault at kernelbase */
	jmp	do_copy
	SET_SIZE(copyout_noerr)

	ENTRY(uzero)
	movl	kernelbase, %eax
	cmpl	%eax, 4(%esp)
	jb	do_zero
	movl	%eax, 4(%esp)	/* force fault at kernelbase */
	jmp	do_zero
	SET_SIZE(uzero)

	ENTRY(ucopy)
	movl	kernelbase, %eax
	cmpl	%eax, 4(%esp)
	jb	1f
	movl	%eax, 4(%esp)	/* force fault at kernelbase */
1:
	cmpl	%eax, 8(%esp)
	jb	do_copy
	movl	%eax, 8(%esp)	/* force fault at kernelbase */
	jmp	do_copy
	SET_SIZE(ucopy)

	ENTRY(ucopystr)
	movl	kernelbase, %eax
	cmpl	%eax, 4(%esp)
	jb	1f
	movl	%eax, 4(%esp)	/* force fault at kernelbase */
1:
	cmpl	%eax, 8(%esp)
	jb	2f
	movl	%eax, 8(%esp)	/* force fault at kernelbase */
2:
	/* do_copystr expects the lofault address in %eax */
	movl	%gs:CPU_THREAD, %eax
	movl	T_LOFAULT(%eax), %eax
	jmp	do_copystr
	SET_SIZE(ucopystr)

#endif	/* __i386 */

#ifdef DEBUG
	.data
.kcopy_panic_msg:
	.string "kcopy: arguments below kernelbase"
.bcopy_panic_msg:
	.string "bcopy: arguments below kernelbase"
.kzero_panic_msg:
        .string "kzero: arguments below kernelbase"
.bzero_panic_msg:
	.string	"bzero: arguments below kernelbase"
.copyin_panic_msg:
	.string "copyin: kaddr argument below kernelbase"
.xcopyin_panic_msg:
	.string	"xcopyin: kaddr argument below kernelbase"
.copyout_panic_msg:
	.string "copyout: kaddr argument below kernelbase"
.xcopyout_panic_msg:
	.string	"xcopyout: kaddr argument below kernelbase"
.copystr_panic_msg:
	.string	"copystr: arguments in user space"
.copyinstr_panic_msg:
	.string	"copyinstr: kaddr argument not in kernel address space"
.copyoutstr_panic_msg:
	.string	"copyoutstr: kaddr argument not in kernel address space"
.cpyin_ne_pmsg:
	.string "copyin_noerr: argument not in kernel address space"
.cpyout_ne_pmsg:
	.string "copyout_noerr: argument not in kernel address space"
#endif

#endif	/* __lint */
