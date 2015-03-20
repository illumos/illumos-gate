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
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/asm_linkage.h>
#include <sys/trap.h>

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
	 * already in %rdi, arg1 already in %rsi, etc.). %rax has result of
	 * call.
	 */

	/*
	 * Uses fasttrap, based on lib/libc/amd64/sys/gettimeofday.s
	 */
	ENTRY_NP(__vdso_gettimeofday)
	pushq	%rdi		/* pointer to timeval */
	movl	$T_GETHRESTIME, %eax
	int	$T_FASTTRAP
	/*
	 *	gethrestime trap returns seconds in %rax, nsecs in %edx
	 *	need to convert nsecs to usecs & store into area pointed
	 *	to by struct timeval * argument.
	 */
	popq	%rcx		/* pointer to timeval */
	jrcxz	1f		/* bail if we get a null pointer */
	movq	%rax, (%rcx)	/* store seconds into timeval ptr */
	movl	$274877907, %eax /* divide by 1000 as impl. by gcc */
	imull	%edx		/* See Hacker's Delight pg 162 */
	sarl	$6, %edx	/* simplified by 0 <= nsec <= 1e9 */
	movq	%rdx, 8(%rcx)	/* store usecs into timeval ptr + 8. */
1:
	xorq	%rax, %rax	/* return 0 */
	ret
	SET_SIZE(__vdso_gettimeofday)

	/*
	 * Uses fasttrap, based on lib/libc/amd64/sys/gettimeofday.s, but only
	 * returns seconds. This is based on what the kernel's gtime function
	 * will do.
	 */
	ENTRY_NP(__vdso_time)
	pushq	%rdi		/* pointer to time_t */
	movl	$T_GETHRESTIME, %eax
	int	$T_FASTTRAP
	/*
	 *	gethrestime trap returns seconds in %rax
	 *	store secs into area pointed by time_t * argument.
	 */
	popq	%rcx		/* pointer to time_t */
	jrcxz	1f		/* don't save if we get a null pointer */
	movq	%rax, (%rcx)	/* store seconds into time_t ptr */
1:
	ret			/* return seconds in %rax */
	SET_SIZE(__vdso_time)

	/*
	 * Does not use fasttrap since there more work to emulate than we can
	 * do with a fasttrap.
	 */
	ENTRY_NP(__vdso_clock_gettime)
	movq $LX_SYS_clock_gettime, %rax
	syscall
	ret
	SET_SIZE(__vdso_clock_gettime)

	/*
	 * Uses fasttrap.
	 * getcpu takes 3 pointers but we only support saving the cpu ID into
	 * the first pointer.
	 */
	ENTRY_NP(__vdso_getcpu)
	pushq	%rdi		/* pointer to int */
	movl	$T_GETLGRP, %eax
	int	$T_FASTTRAP
	/*
	 *	getlgrp trap returns CPU ID in %eax
	 *	store it into area pointed by int * argument.
	 */
	popq	%rcx		/* pointer to int */
	jrcxz	1f		/* don't save if we get a null pointer */
	movl	%eax, (%rcx)	/* store CPU ID into int ptr */
1:
	xorq	%rax, %rax	/* return 0 */
	ret
	SET_SIZE(__vdso_getcpu)
#endif
