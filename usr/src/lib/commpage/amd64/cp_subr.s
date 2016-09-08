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
 * hrtime_t
 * __cp_tsc_read(comm_page_t *cp)
 *
 * Stack usage: 0 bytes
 */
	ENTRY_NP(__cp_tsc_read)
	movl	CP_TSC_TYPE(%rdi), %esi
	movl	CP_TSC_NCPU(%rdi), %r8d
	leaq	CP_TSC_SYNC_TICK_DELTA(%rdi), %r9

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
	cmpl	$0, %esi
	jne	1f
	ret
1:
	/*
	 * When cp_tsc_ncpu is non-zero, it indicates the length of the
	 * cp_tsc_sync_tick_delta array, which contains per-CPU offsets for the
	 * TSC.  The CPU ID furnished by the IA32_TSC_AUX register via rdtscp
	 * is used to look up an offset value in that array and apply it to the
	 * TSC reading.
	 */
	movq	(%r9, %rcx, 8), %rdx
	addq	%rdx, %rax
	ret

2:
	/*
	 * Without rdtscp, there is no way to perform a TSC reading and
	 * simultaneously query the current CPU.  If tsc_ncpu indicates that
	 * per-CPU TSC offsets are present, the ID of the current CPU is
	 * queried before performing a TSC reading.  It will be later compared
	 * to a second CPU ID lookup to catch CPU migrations.
	 *
	 * This method will catch all but the most pathological scheduling.
	 */
	cmpl	$0, %r8d
	je	3f
	movl	$GETCPU_GDT_OFFSET, %edx
	lsl	%dx, %edx

3:
	/* Save the most recently queried CPU ID for later comparison. */
	movl	%edx, %r10d

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
	 * called in the first place.  The only sane action is to abort.
	 * The easiest means in this context is via SIGILL.
	 */
	ud2a

7:
	shlq	$0x20, %rdx
	orq	%rdx, %rax

	/*
	 * Query the current CPU again if a per-CPU offset is being applied to
	 * the TSC reading.  If the result differs from the earlier reading,
	 * then a migration has occured and the TSC must be read again.
	 */
	cmpl	$0, %r8d
	je	8f
	movl	$GETCPU_GDT_OFFSET, %edx
	lsl	%dx, %edx
	cmpl	%edx, %r10d
	jne	3b
	movq	(%r9, %rdx, 8), %rdx
	addq	%rdx, %rax
8:
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
