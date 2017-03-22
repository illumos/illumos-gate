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

	.file	"cp_subr.s"

/*
 * These are cloned from TSC and time related code in the kernel.  They should
 * be kept in sync in the case that the source values are changed.
 * See: uts/i86pc/os/timestamp.c
 */
#define	NSEC_SHIFT	5
#define	ADJ_SHIFT	4
#define	NANOSEC		0x3b9aca00

/*
 * For __cp_tsc_read calls which incur looping retries due to CPU migration,
 * this represents the maximum number of tries before bailing out.
 */
#define	TSC_READ_MAXLOOP	0x4

/*
 * hrtime_t
 * __cp_tsc_read(comm_page_t *cp)
 *
 * Stack usage: 0 bytes
 */
	ENTRY_NP(__cp_tsc_read)
	movl	CP_TSC_TYPE(%rdi), %esi
	movl	CP_TSC_NCPU(%rdi), %r8d

	cmpl	$TSC_TSCP, %esi
	jne	2f
	rdtscp
	/*
	 * When the TSC is read, the low 32 bits are placed in %eax while the
	 * high 32 bits are placed in %edx.  They are shifted and ORed together
	 * to obtain the full 64-bit value.
	 */
	shlq	$0x20, %rdx
	orq	%rdx, %rax

	/*
	 * A zeroed cp_tsc_ncpu (currently held in r8d) indicates that no
	 * per-CPU TSC offsets are required.
	 */
	testl	%r8d, %r8d
	jnz	1f
	ret

1:
	/*
	 * A non-zero cp_tsc_ncpu indicates the array length of
	 * cp_tsc_sync_tick_delta containing per-CPU offsets which are applied
	 * to TSC readings.  The CPU ID furnished by the IA32_TSC_AUX register
	 * via rdtscp (placed in rcx) is used to look up an offset value in
	 * that array and apply it to the TSC value.
	 */
	leaq	CP_TSC_SYNC_TICK_DELTA(%rdi), %r9
	movq	(%r9, %rcx, 8), %rdx
	addq	%rdx, %rax
	ret

2:
	/*
	 * TSC reading without RDTSCP
	 *
	 * Check if handling for per-CPU TSC offsets is required.  If not,
	 * immediately skip to the the appropriate steps to perform a rdtsc.
	 *
	 * If per-CPU offsets are present, the TSC reading process is more
	 * complicated.  Without rdtscp, there is no way to simultaneously read
	 * the TSC and query the current CPU.  In order to "catch" migrations
	 * during execution, the CPU ID is queried before and after rdtsc.  The
	 * execution is repeated if results differ, subject to a loop limit.
	 */
	xorq	%r9, %r9
	testl	%r8d, %r8d
	jz	3f

	/*
	 * Load the address of the per-CPU offset array, since it is needed.
	 * The attempted loop count is kept in r8.
	 */
	leaq	CP_TSC_SYNC_TICK_DELTA(%rdi), %r9
	xorl	%r8d, %r8d

	/* Query the CPU ID and stash it in r10 for later comparison */
	movl	$GETCPU_GDT_OFFSET, %edx
	lsl	%dx, %edx
	movl	%edx, %r10d

3:
	cmpl	$TSC_RDTSC_MFENCE, %esi
	jne	4f
	mfence
	rdtsc
	jmp	7f

4:
	cmpl	$TSC_RDTSC_LFENCE, %esi
	jne	5f
	lfence
	rdtsc
	jmp	7f

5:
	cmpl	$TSC_RDTSC_CPUID, %esi
	jne	6f
	/*
	 * Since the amd64 ABI dictates that %rbx is callee-saved, it must be
	 * preserved here.  Its contents will be overwritten when cpuid is used
	 * as a serializing instruction.
	 */
	movq	%rbx, %r11
	xorl	%eax, %eax
	cpuid
	rdtsc
	movq	%r11, %rbx
	jmp	7f

6:
	/*
	 * Other protections should have prevented this function from being
	 * called in the first place.  Since callers must handle a failure from
	 * CPU migration looping, yield the same result as a bail-out: 0
	 */
	xorl	%eax, %eax
	ret

7:
	shlq	$0x20, %rdx
	orq	%rdx, %rax

	/*
	 * With the TSC reading in-hand, check if any per-CPU offset handling
	 * is required.  The address to the array of deltas (r9) will not have
	 * been populated if offset handling is unecessary.
	 */
	testq	%r9, %r9
	jnz	8f
	ret

8:
	movl	$GETCPU_GDT_OFFSET, %edx
	lsl	%dx, %edx
	cmpl	%edx, %r10d
	jne	9f
	movq	(%r9, %rdx, 8), %rdx
	addq	%rdx, %rax
	ret

9:
	/*
	 * It appears that a migration has occurred between the first CPU ID
	 * query and now.  Check if the loop limit has been broken and retry if
	 * that's not the case.
	 */
	cmpl	$TSC_READ_MAXLOOP, %r8d
	jge	10f
	incl	%r8d
	movl	%edx, %r10d
	jmp	3b

10:
	/* Loop limit was reached. Return bail-out value of 0. */
	xorl	%eax, %eax
	ret

	SET_SIZE(__cp_tsc_read)


/*
 * uint_t
 * __cp_getcpu(comm_page_t *)
 *
 * Stack usage: 0 bytes
 */
	ENTRY_NP(__cp_getcpu)
	movl	CP_TSC_TYPE(%rdi), %edi
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
	SET_SIZE(__cp_getcpu)

/*
 * hrtime_t
 * __cp_gethrtime(comm_page_t *cp)
 *
 * Stack usage: 0x20 local + 0x8 call = 0x28 bytes
 *
 * %rsp+0x00 - hrtime_t tsc_last
 * %rsp+0x08 - hrtime_t hrtime_base
 * %rsp+0x10 - commpage_t *cp
 * %rsp+0x18 - int hres_lock
 */
	ENTRY_NP(__cp_gethrtime)
	subq	$0x20, %rsp
	movq	%rdi, 0x10(%rsp)
1:
	movl	CP_HRES_LOCK(%rdi), %r9d
	movl	%r9d, 0x18(%rsp)

	movq	CP_TSC_LAST(%rdi), %rax
	movq	CP_TSC_HRTIME_BASE(%rdi), %rdx
	movq	%rax, (%rsp)
	movq	%rdx, 0x8(%rsp)

	call	__cp_tsc_read

	/*
	 * Failure is inferred from a TSC reading of 0.  The normal fasttrap
	 * mechanism can be used as a fallback in such cases.
	 */
	testq	%rax, %rax
	jz	6f

	movq	0x10(%rsp), %rdi
	movl	0x18(%rsp), %r9d
	movl	CP_HRES_LOCK(%rdi), %edx
	andl	$0xfffffffe, %r9d
	cmpl	%r9d, %edx
	jne	1b

	/*
	 * The in-kernel logic for calculating hrtime performs several checks
	 * to protect against edge cases.  That logic is summarized as:
	 * if (tsc >= tsc_last) {
	 *         delta -= tsc_last;
	 * } else if (tsc >= tsc_last - 2*tsc_max_delta) {
	 *         delta = 0;
	 * } else {
	 *         delta = MIN(tsc, tsc_resume_cap);
	 * }
	 *
	 * The below implementation achieves the same result, although it is
	 * structured for speed and optimized for the fast path:
	 *
	 * delta = tsc - tsc_last;
	 * if (delta < 0) {
	 *         delta += (tsc_max_delta << 1);
	 *         if (delta >= 0) {
	 *                 delta = 0;
	 *         } else {
	 *                 delta = MIN(tsc, tsc_resume_cap);
	 *         }
	 * }
	 */
	movq	(%rsp), %rdx
	subq	%rdx, %rax		/* delta = tsc - tsc_last */
	jbe	3f			/* if (delta < 0) */

2:
	/*
	 * Optimized TSC_CONVERT_AND_ADD:
	 * hrtime_base += (tsc_delta * nsec_scale) >> (32 - NSEC_SHIFT)
	 *
	 * Since the multiply and shift are done in 128-bit, there is no need
	 * to worry about overflow.
	 */
	movl	CP_NSEC_SCALE(%rdi), %ecx
	mulq	%rcx
	shrdq	$_CONST(32 - NSEC_SHIFT), %rdx, %rax
	movq	0x8(%rsp), %r8
	addq	%r8, %rax

	addq	$0x20, %rsp
	ret

3:
	movq	%rax, %r9		/* save (tsc - tsc_last) in r9 */
	movl	CP_TSC_MAX_DELTA(%rdi), %ecx
	sall	$1, %ecx
	addq	%rcx, %rax		/* delta += (tsc_max_delta << 1) */
	jae	4f			/* delta < 0 */
	xorq	%rax, %rax
	jmp	2b

4:
	/*
	 * Repopulate %rax with the TSC reading by adding tsc_last to %r9
	 * (which holds tsc - tsc_last)
	 */
	movq	(%rsp), %rax
	addq	%r9, %rax

	/* delta = MIN(tsc, resume_cap) */
	movq	CP_TSC_RESUME_CAP(%rdi), %rcx
	cmpq	%rcx, %rax
	jbe	5f
	movq	%rcx, %rax
5:
	jmp	2b

6:
	movl	$T_GETHRTIME, %eax
	int	$T_FASTTRAP
	addq	$0x20, %rsp
	ret

	SET_SIZE(__cp_gethrtime)

/*
 * int
 * __cp_clock_gettime_monotonic(comm_page_t *cp, timespec_t *tsp)
 *
 * Stack usage: 0x8 local + 0x8 call + 0x28 called func. = 0x38 bytes
 *
 * %rsp+0x00 - timespec_t *tsp
 */
	ENTRY_NP(__cp_clock_gettime_monotonic)
	subq	$0x8, %rsp
	movq	%rsi, (%rsp)

	call	__cp_gethrtime

	/*
	 * Convert from hrtime_t (int64_t in nanoseconds) to timespec_t.
	 * This uses the same approach as hrt2ts, although it has been updated
	 * to utilize 64-bit math.
	 * 1 / 1,000,000,000 =
	 * 1000100101110000010111110100000100110110101101001010110110011B-26
	 * = 0x112e0be826d694b3 * 2^-26
	 *
	 * secs = (nsecs * 0x112e0be826d694b3) >> 26
	 *
	 * In order to account for the 2s-compliment of negative inputs, a
	 * final operation completes the process:
	 *
	 * secs -= (nsecs >> 63)
	 */
	movq	%rax, %r11
	movq	$0x112e0be826d694b3, %rdx
	imulq	%rdx
	sarq	$0x1a, %rdx
	movq	%r11, %rax
	sarq	$0x3f, %rax
	subq	%rax, %rdx
	movq	(%rsp), %rsi
	movq	%rdx, (%rsi)
	/*
	 * Populating tv_nsec is easier:
	 * tv_nsec = nsecs - (secs * NANOSEC)
	 */
	imulq	$NANOSEC, %rdx, %rdx
	subq	%rdx, %r11
	movq	%r11, 0x8(%rsi)

	xorl	%eax, %eax
	addq	$0x8, %rsp
	ret
	SET_SIZE(__cp_clock_gettime_monotonic)

/*
 * int
 * __cp_clock_gettime_realtime(comm_page_t *cp, timespec_t *tsp)
 *
 * Stack usage: 0x18 local + 0x8 call + 0x28 called func. = 0x48 bytes
 *
 * %rsp+0x00 - commpage_t *cp
 * %rsp+0x08 - timespec_t *tsp
 * %rsp+0x10 - int hres_lock
 */
	ENTRY_NP(__cp_clock_gettime_realtime)
	subq	$0x18, %rsp
	movq	%rdi, (%rsp)
	movq	%rsi, 0x8(%rsp)

1:
	movl	CP_HRES_LOCK(%rdi), %eax
	movl	%eax, 0x10(%rsp)

	call	__cp_gethrtime
	movq	(%rsp), %rdi
	movq	CP_HRES_LAST_TICK(%rdi), %rdx
	subq	%rdx, %rax			/* nslt = hrtime - last_tick */
	jb	1b
	movq	CP_HRESTIME(%rdi), %r9
	movq	_CONST(CP_HRESTIME + CP_HRESTIME_INCR)(%rdi), %r10
	movl	CP_HRESTIME_ADJ(%rdi), %r11d

	addq	%rax, %r10			/* now.tv_nsec += nslt */

	cmpl	$0, %r11d
	jb	4f				/* hres_adj > 0 */
	ja	6f				/* hres_adj < 0 */

2:
	cmpq	$NANOSEC, %r10
	jae	8f				/* tv_nsec >= NANOSEC */

3:
	movl	0x10(%rsp), %eax
	movl	CP_HRES_LOCK(%rdi), %edx
	andl	$0xfffffffe, %edx
	cmpl	%eax, %edx
	jne	1b

	movq	0x8(%rsp), %rsi
	movq	%r9, (%rsi)
	movq	%r10, 0x8(%rsi)

	xorl	%eax, %eax
	addq	$0x18, %rsp
	ret


4:						/* hres_adj > 0 */
	sarq	$ADJ_SHIFT, %rax
	cmpl	%r11d, %eax
	jbe	5f
	movl	%r11d, %eax
5:
	addq	%rax, %r10
	jmp	2b

6:						/* hres_adj < 0 */
	sarq	$ADJ_SHIFT, %rax
	negl	%r11d
	cmpl	%r11d, %eax
	jbe	7f
	movl	%r11d, %eax
7:
	subq	%rax, %r10
	jmp	2b

8:						/* tv_nsec >= NANOSEC */
	subq	$NANOSEC, %r10
	incq	%r9
	cmpq	$NANOSEC, %r10
	jae	8b
	jmp	3b

	SET_SIZE(__cp_clock_gettime_realtime)
