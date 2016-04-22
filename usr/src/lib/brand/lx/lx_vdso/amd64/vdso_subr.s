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

#endif /* lint */
