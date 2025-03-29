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
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/asm_linkage.h>

/*
 * TSC math functions that require multiplication of 64-bit numbers with
 * intermediate steps requiring 128-bit precision.
 *
 * See block comment in vmm.c for more details.
 */


/*
 * calc_freq_multiplier: calculates the ratio of guest_hz / host_hz, with
 * `frac_size` fractional bits.
 *
 * (guest_hz * (1 << FRAC_SIZE)) / host_hz
 *
 * Note: this will generate a #DE if:
 * - the integer portion of the ratio does not fit into (64 - FRAC_SIZE) bits
 * - host_hz is 0
 * Callers should validate input appropriately.
 *
 *
 * uint64_t calc_freq_multiplier(uint64_t guest_hz, uint64_t host_hz,
 *     uint32_t frac_size)
 * %rdi: uint64_t guest_hz
 * %rsi: uint64_t host_hz
 * %edx: uint32_t frac_size
 */
ENTRY_NP(calc_freq_multiplier)
	/*
	 * Create scaling factor: 1 << frac_size
	 * Store result in %rax
	 */
	movl $1, %eax
	movl %edx, %ecx
	shlq %cl, %rax

	/*
	 * Multiply: guest_hz (%rdi) * scaling_factor (%rax)
	 * Result is in %rdx:%rax
	 */
	mulq %rdi

	/* Divide: result by host_hz (%rsi) */
	divq %rsi
	ret
SET_SIZE(calc_freq_multiplier)


/*
 * scale_tsc: Scales a TSC value based on a frequency multiplier with
 * FRAC_SIZE fractional bits.
 *
 * (tsc * multiplier) >> FRAC_SIZE
 *
 *
 * uint64_t scale_tsc(uint64_t tsc, uint64_t multiplier, uint32_t frac_size)
 * %rdi: uint64_t tsc
 * %rsi: uint64_t multiplier
 * %edx: uint32_t frac_size
 */
ENTRY_NP(scale_tsc)
	/* Save `frac_size` */
	mov %edx, %ecx

	/*
	 * Multiply tsc (%rdi) * multiplier (%rsi)
	 * mulq result is in %rdx:%rax
	 */
	movq %rdi, %rax
	mulq %rsi

	/*
	 * Shift the 128-bit product right `frac_size` bits:
	 * - shift lower 64 bits right, `frac_size` bits
	 * - shift upper 64 bits left, (64 - `frac_size`) bits
	 * - bitwise OR upper bits and lower bits
	 */

	/* Shift lower 64 bits right `frac_size` */
	shrq %cl, %rax

	/* Compute 64 - FRAC_SIZE and store result in %cl */
	movl %ecx, %r9d
	movl $64, %ecx
	subl %r9d, %ecx

	/* Shift upper 64 bits left, (64 - `frac_size`) bits */
	shlq %cl, %rdx

	/* Bitwise OR upper and lower bits */
	orq %rdx, %rax

	ret
SET_SIZE(scale_tsc)
