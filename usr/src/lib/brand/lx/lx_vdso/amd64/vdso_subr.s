/*
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 */

/*
 * Copyright 2016 Joyent, Inc.
 */


#include <sys/asm_linkage.h>
#include <sys/lx_syscalls.h>
#include <vdso_defs.h>

#if defined(lint)

comm_page_t *
__vdso_find_commpage()
{}

long
__vdso_sys_clock_gettime(uint_t clock_id, timespec_t *tp)
{}

int
__vdso_sys_gettimeofday(timespec_t *tp, struct lx_timezone *tz)
{}

time_t
__vdso_sys_time(timespec_t *tp)
{}

#else /* lint */

	ENTRY_NP(__vdso_find_commpage)
	leaq	0x0(%rip), %rax
	andq	$LX_VDSO_ADDR_MASK, %rax
	addq	$LX_VDSO_SIZE, %rax
	ret
	SET_SIZE(__vdso_find_commpage)

	ENTRY_NP(__vdso_sys_clock_gettime)
	movl	$LX_SYS_clock_gettime, %eax
	syscall
	ret
	SET_SIZE(__vdso_sys_clock_gettime)

	ENTRY_NP(__vdso_sys_gettimeofday)
	movl	$LX_SYS_gettimeofday, %eax
	syscall
	ret
	SET_SIZE(__vdso_sys_gettimeofday)

	ENTRY_NP(__vdso_sys_time)
	movl	$LX_SYS_time, %eax
	syscall
	ret
	SET_SIZE(__vdso_sys_time)

/*
 * long
 * __vdso_clock_gettime(uint_t, timespec_t *)
 */
	ENTRY_NP(__vdso_clock_gettime)
	subq	$0x18, %rsp
	movl	%edi, (%rsp)
	movq	%rsi, 0x8(%rsp)

	call	__vdso_find_commpage
	movq	%rax, 0x10(%rsp)

	movq	%rax, %rdi
	call	__cp_can_gettime
	cmpl	$0, %eax
	je	5f

	/*
	 * Restore the original args/stack (with commpage pointer in rdx)
	 * This enables the coming tail-call to the desired function, be it
	 * __cp_clock_gettime_* or __vdso_sys_clock_gettime.
	 */
	movl	(%rsp), %edi
	movq	0x8(%rsp), %rsi
	movq	0x10(%rsp), %rdx
	addq	$0x18, %rsp

	cmpl	$LX_CLOCK_REALTIME, %edi
	jne	2f
1:
	movq	%rdx, %rdi
	jmp	__cp_clock_gettime_realtime

2:
	cmpl	$LX_CLOCK_MONOTONIC, %edi
	jne	4f
3:
	movq	%rdx, %rdi
	jmp	__cp_clock_gettime_monotonic

4:
	cmpl	$LX_CLOCK_REALTIME_COARSE, %edi
	je	1b
	cmpl	$LX_CLOCK_MONOTONIC_RAW, %edi
	je	3b
	cmpl	$LX_CLOCK_MONOTONIC_COARSE, %edi
	je	3b
	jmp	6f

5:
	/*
	 * When falling through from a failed cp_can_gettime, the stack
	 * allocation must be released before a tail-call is made to the
	 * fallback syscall function.
	 */
	addq	$0x18, %rsp

6:
	/* Let the real syscall handle all other cases */
	jmp	__vdso_sys_clock_gettime
	SET_SIZE(__vdso_clock_gettime)


#endif /* lint */
