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
	call	1f
1:	popl	%eax
	andl	$LX_VDSO_ADDR_MASK, %eax
	addl	$LX_VDSO_SIZE, %eax
	ret
	SET_SIZE(__vdso_find_commpage)

	ENTRY_NP(__vdso_sys_clock_gettime)
	movl	$LX_SYS_clock_gettime, %eax
	movl	0x4(%esp), %ebx
	movl	0x8(%esp), %ecx
	int	$0x80
	ret
	SET_SIZE(__vdso_sys_clock_gettime)

	ENTRY_NP(__vdso_sys_gettimeofday)
	movl	$LX_SYS_gettimeofday, %eax
	movl	0x4(%esp), %ebx
	movl	0x8(%esp), %ecx
	int	$0x80
	ret
	SET_SIZE(__vdso_sys_gettimeofday)

	ENTRY_NP(__vdso_sys_time)
	movl	$LX_SYS_time, %eax
	movl	0x4(%esp), %ebx
	int	$0x80
	ret
	SET_SIZE(__vdso_sys_time)

	ENTRY_NP(__vsyscall)
	/*
	 * On 32-bit Linux, the VDSO entry point (specified by e_entry)
	 * provides a potentially accelerated means to vector into the kernel.
	 * Normally this means using 'sysenter' with a Linux-custom calling
	 * convention so programs expecting int80 behavior are not required to
	 * change how arguments are passed.
	 *
	 * The SunOS sysenter entry point does _not_ tolerate such a departure
	 * from convention, so if this function is updated to use sysenter, it
	 * must properly marshal arguments onto the stack from the int80 style.
	 * Such an enhancement can only occur once sysenter receives the same
	 * branding hooks as syscall and int80.
	 */
	int	$0x80
	ret
	SET_SIZE(__vsyscall)

#endif /* lint */
