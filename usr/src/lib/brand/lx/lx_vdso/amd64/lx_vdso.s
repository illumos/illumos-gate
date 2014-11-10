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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <sys/asm_linkage.h>

/*
 * lx vDSO emulation library
 *
 * This so needs to look like the correct Linux vDSO elf library. We cannot
 * use any native symbols or link with any native libraries, particularly libc.
 */

#define	LX_SYS_gettimeofday	96
#define	LX_SYS_time		201
#define	LX_SYS_clock_gettime	228
#define	LX_SYS_getcpu		309

#if defined(lint)
int
__vdso_gettimeofday(void *tp, void *tz)
{}

time_t
__vdso_time(void *tp)
{}

time_t
__vdso_clock_gettime(uintptr_t id, void *tp)
{}

int
__vdso_getcpu(void *cpu, void *np, void *cp)
{}

#else /* lint */

	/*
	 * We know the arguments are already in the correct registers (e.g. arg0
	 * already in %rdi, arg1 already in %rsi, etc.). %rax has result of call.
	 */
	ENTRY_NP(__vdso_gettimeofday)
	movq $LX_SYS_gettimeofday, %rax
	syscall
	ret
	SET_SIZE(__vdso_gettimeofday)

	ENTRY_NP(__vdso_time)
	movq $LX_SYS_time, %rax
	syscall
	ret
	SET_SIZE(__vdso_time)

	ENTRY_NP(__vdso_clock_gettime)
	movq $LX_SYS_clock_gettime, %rax
	syscall
	ret
	SET_SIZE(__vdso_clock_gettime)

	ENTRY_NP(__vdso_getcpu)
	movq $LX_SYS_getcpu, %rax
	syscall
	ret
	SET_SIZE(__vdso_getcpu)
#endif
