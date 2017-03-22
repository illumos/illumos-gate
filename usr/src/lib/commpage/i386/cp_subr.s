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
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/asm_linkage.h>
#include <sys/segments.h>
#include <sys/time_impl.h>
#include <sys/tsc.h>
#include <cp_offsets.h>

#define	GETCPU_GDT_OFFSET	SEL_GDT(GDT_CPUID, SEL_UPL)

/*
 * For __cp_tsc_read calls which incur looping retries due to CPU migration,
 * this represents the maximum number of tries before bailing out.
 */
#define	TSC_READ_MAXLOOP	0x4

	.file	"cp_subr.s"

/*
 * hrtime_t
 * __cp_tsc_read(comm_page_t *cp)
 *
 * Stack usage: 0x18 bytes
 *
 * %ebp-0x00 - frame pointer
 * %ebp-0x04 - saved %edi
 * %ebp-0x08 - saved %esi
 * %ebp-0x0c - CPU ID
 * %ebp-0x10 - loop count
 * %ebp-0x14 - saved %ebx (during cpuid)
 */
	ENTRY_NP(__cp_tsc_read)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%edi
	pushl	%esi
	subl	$0x8, %esp

	movl	0x8(%ebp), %edi
	movl	CP_TSC_TYPE(%edi), %eax
	movl	CP_TSC_NCPU(%edi), %esi
	cmpl	$TSC_TSCP, %eax
	jne	3f
	rdtscp
	cmpl	$0, %esi
	jne	2f
1:
	addl	$0x8, %esp
	popl	%esi
	popl	%edi
	leave
	ret
2:
	/*
	 * When cp_tsc_ncpu is non-zero, it indicates the length of the
	 * cp_tsc_sync_tick_delta array, which contains per-CPU offsets for the
	 * TSC.  The CPU ID furnished by the IA32_TSC_AUX register via rdtscp
	 * is used to look up an offset value in that array and apply it to the
	 * TSC reading.
	 */
	leal	CP_TSC_SYNC_TICK_DELTA(%edi), %esi
	leal	(%esi, %ecx, 8), %ecx
	addl	(%ecx), %eax
	adcl	0x4(%ecx), %edx
	jmp	1b

3:
	testl	%esi, %esi
	jz	4f

	movl	$0, (%esp)
	mov	$GETCPU_GDT_OFFSET, %eax
	lsl	%ax, %eax
	movl	%eax, 0x4(%esp)
	movl	CP_TSC_TYPE(%edi), %eax

4:
	cmpl	$TSC_RDTSC_MFENCE, %eax
	jne	5f
	mfence
	rdtsc
	jmp	8f

5:
	cmpl	$TSC_RDTSC_LFENCE, %eax
	jne	6f
	lfence
	rdtsc
	jmp	8f

6:
	cmpl	$TSC_RDTSC_CPUID, %eax
	jne	7f
	pushl	%ebx
	xorl	%eax, %eax
	cpuid
	rdtsc
	popl	%ebx
	jmp	8f

7:
	/*
	 * Other protections should have prevented this function from being
	 * called in the first place.  Since callers must handle a failure from
	 * CPU migration looping, yield the same result as a bail-out: 0
	 */
	xorl	%eax, %eax
	xorl	%edx, %edx
	jmp	1b

8:

	cmpl	$0, %esi
	je	1b
	/*
	 * With a TSC reading in-hand, confirm that the thread has not migrated
	 * since the cpu_id was first checked.
	 */
	movl	$GETCPU_GDT_OFFSET, %ecx
	lsl	%cx, %ecx
	movl	0x4(%esp), %esi
	cmpl	%ecx, %esi
	jne	9f

	/* Grab the per-cpu offset and add it to the TSC result */
	leal	CP_TSC_SYNC_TICK_DELTA(%edi), %esi
	leal	(%esi, %ecx, 8), %ecx
	addl	(%ecx), %eax
	adcl	0x4(%ecx), %edx
	jmp	1b

9:
	/*
	 * It appears that a migration has occurred between the first CPU ID
	 * query and now.  Check if the loop limit has been broken and retry if
	 * that's not the case.
	 */
	movl	(%esp), %eax
	cmpl	$TSC_READ_MAXLOOP, %eax
	jge	10f

	incl	%eax
	movl	%eax, (%esp)
	movl	%ecx, 0x4(%esp)
	movl	CP_TSC_NCPU(%edi), %esi
	movl	CP_TSC_TYPE(%edi), %eax
	jmp	4b

10:
	/* Loop limit was reached. Return bail-out value of 0. */
	xorl	%eax, %eax
	xorl	%edx, %edx
	jmp	1b

	SET_SIZE(__cp_tsc_read)

/*
 * hrtime_t
 * __cp_gethrtime_fasttrap()
 */
	ENTRY_NP(__cp_gethrtime_fasttrap)
	movl	$T_GETHRTIME, %eax
	int	$T_FASTTRAP
	ret
	SET_SIZE(__cp_gethrtime_fasttrap)

/*
 * uint_t
 * __cp_getcpu(uint_t cp_tsc_type)
 */
	ENTRY_NP(__cp_getcpu)
	/*
	 * If RDTSCP is available, it is a quick way to grab the cpu_id which
	 * is stored in the TSC_AUX MSR by the kernel.
	 */
	movl	4(%esp), %eax
	movl	CP_TSC_TYPE(%eax), %eax
	cmpl	$TSC_TSCP, %eax
	jne	1f
	rdtscp
	movl	%ecx, %eax
	ret
1:
	mov	$GETCPU_GDT_OFFSET, %eax
	lsl	%ax, %eax
	ret
	SET_SIZE(__cp_getcpu)
