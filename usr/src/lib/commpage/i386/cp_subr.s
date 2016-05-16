/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/asm_linkage.h>
#include <sys/segments.h>
#include <sys/time_impl.h>
#include <sys/tsc.h>

#define	GETCPU_GDT_OFFSET	SEL_GDT(GDT_CPUID, SEL_UPL)

	.file	"cp_subr.s"

/*
 * hrtime_t
 * __cp_tsc_read(uint_t cp_tsc_type)
 */
	ENTRY_NP(__cp_tsc_read)
	movl	4(%esp), %eax
	cmpl	$TSC_TSCP, %eax
	je	1f
	cmpl	$TSC_RDTSC_MFENCE, %eax
	je	2f
	cmpl	$TSC_RDTSC_LFENCE, %eax
	je	3f
	cmpl	$TSC_RDTSC_CPUID, %eax
	je	4f
	ud2a	/* abort with SIGILL */
1:
	rdtscp
	ret
2:
	mfence
	rdtsc
	ret
3:
	lfence
	rdtsc
	ret
4:
	pushl	%ebx
	xorl	%eax, %eax
	cpuid
	rdtsc
	popl	%ebx
	ret
	SET_SIZE(__cp_tsc_read)

/*
 * hrtime_t
 *  __cp_tsc_readcpu(uint_t cp_tsc_type, uint_t *cpu_id)
 */
	ENTRY_NP(__cp_tsc_readcpu)
	/*
	 * Both time and cpu_id can be queried quickly (using few registers) on
	 * systems which support RDTSCP.  On each cpu, the cpu_id is stored in
	 * the TSC_AUX MSR by the kernel.
	 */
	movl	4(%esp), %eax
	cmpl	$TSC_TSCP, %eax
	jne	1f
	rdtscp
	pushl	%eax
	movl	0xc(%esp), %eax
	movl	%ecx, (%eax)
	popl	%eax
	ret
1:
	/*
	 * Since the other methods of querying the TSC and cpu_id are
	 * vulnurable to CPU migrations, build a proper stack frame so a more
	 * complicated and thorough check and be performed.
	 */
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%edi
	pushl	%esi
	movl	%eax, %edi
2:
	mov	$GETCPU_GDT_OFFSET, %eax
	lsl	%ax, %eax
	movl	%eax, %esi
	cmpl	$TSC_RDTSC_MFENCE, %edi
	je	3f
	cmpl	$TSC_RDTSC_LFENCE, %edi
	je	4f
	cmpl	$TSC_RDTSC_CPUID, %edi
	je	5f
	ud2a	/* abort with SIGILL */
3:
	mfence
	rdtsc
	jmp 6f
4:
	lfence
	rdtsc
	jmp 6f
5:
	pushl	%ebx
	xorl	%eax, %eax
	cpuid
	rdtsc
	popl	%ebx
6:
	/*
	 * With a TSC reading in-hand, confirm that the thread has not migrated
	 * since the cpu_id was first checked.
	 */
	pushl	%eax
	mov	$GETCPU_GDT_OFFSET, %eax
	lsl	%ax, %eax
	cmpl	%eax, %esi
	jne	2b
	movl	0xc(%ebp), %edi
	mov	%eax, (%edi)
	popl	%eax
	popl	%esi
	popl	%edi
	leave
	ret
	SET_SIZE(__cp_tsc_readcpu)

/*
 * uint_t
 * __cp_do_getcpu(uint_t cp_tsc_type)
 */
	ENTRY_NP(__cp_do_getcpu)
	/*
	 * If RDTSCP is available, it is a quick way to grab the cpu_id which
	 * is stored in the TSC_AUX MSR by the kernel.
	 */
	movl	4(%esp), %eax
	cmpl	$TSC_TSCP, %eax
	jne	1f
	rdtscp
	movl	%ecx, %eax
	ret
1:
	mov	$GETCPU_GDT_OFFSET, %eax
	lsl	%ax, %eax
	ret
	SET_SIZE(__cp_do_getcpu)
