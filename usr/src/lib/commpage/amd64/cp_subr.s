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
	cmpl	$TSC_TSCP, %edi
	je	1f
	cmpl	$TSC_RDTSC_MFENCE, %edi
	je	2f
	cmpl	$TSC_RDTSC_LFENCE, %edi
	je	3f
	cmpl	$TSC_RDTSC_CPUID, %edi
	je	4f
	ud2a	/* abort with SIGILL */
1:
	rdtscp
	jmp 5f
2:
	mfence
	rdtsc
	jmp 5f
3:
	lfence
	rdtsc
	jmp 5f
4:
	movq	%rbx, %r11
	xorl	%eax, %eax
	cpuid
	rdtsc
	movq	%r11, %rbx
5:
	shlq	$0x20, %rdx
	orq	%rdx, %rax
	ret
	SET_SIZE(__cp_tsc_read)


/*
 * hrtime_t
 * __cp_tsc_readcpu(uint_t cp_tsc_type, uint_t *cpu_id)
 */
	ENTRY_NP(__cp_tsc_readcpu)
	/*
	 * Both time and cpu_id can be queried quickly (using few registers) on
	 * systems which support RDTSCP.  On each cpu, the cpu_id is stored in
	 * the TSC_AUX MSR by the kernel.
	 */
	cmpl	$TSC_TSCP, %edi
	jne	1f
	rdtscp
	movl	%ecx, (%rsi)
	shlq	$0x20, %rdx
	orq	%rdx, %rax
	ret
1:
	mov	$GETCPU_GDT_OFFSET, %eax
	lsl	%ax, %eax
	movq	%rax, %r11
	cmpl	$TSC_RDTSC_MFENCE, %edi
	je	2f
	cmpl	$TSC_RDTSC_LFENCE, %edi
	je	3f
	cmpl	$TSC_RDTSC_CPUID, %edi
	je	4f
	ud2a	/* abort with SIGILL */
2:
	mfence
	rdtsc
	jmp 5f
3:
	lfence
	rdtsc
	jmp 5f
4:
	movq	%rbx, %r10
	xorl	%eax, %eax
	cpuid
	rdtsc
	movq	%r10, %rbx
5:
	shlq	%rdx
	orq	%rax, %rdx
	/*
	 * With a TSC reading in-hand, confirm that the thread has not migrated
	 * since the cpu_id was first checked.
	 */
	mov	$GETCPU_GDT_OFFSET, %eax
	lsl	%ax, %eax
	cmpq	%rax, %r11
	jne	1b
	movl	%eax, (%rsi)
	movq	%rdx, %rax
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
	cmpl	$TSC_TSCP, %edi
	jne	1f
	rdtscp
	movl	%ecx, %eax
	ret
1:
	mov	$GETCPU_GDT_OFFSET, %eax
	lsl	%ax, %eax
	ret
	SET_SIZE(__cp_do_getcpu)
