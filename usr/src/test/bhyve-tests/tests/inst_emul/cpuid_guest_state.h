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
 * Definitions shared by the harness and payload halves of the cpuid_guest_state
 * test.
 *
 * Copyright 2025 Oxide Computer Company
 */

#ifndef	_CPUID_GUEST_STATE_H
#define	_CPUID_GUEST_STATE_H

/*
 * Fixed test values for leaves 0 and 1, taken from a representative test VM on
 * an AMD host machine.
 *
 * Leaf 0's values are never modified by guest CPU state. Although this
 * particular test doesn't rely on the value in eax to determine what other
 * leaves to query, set it to 0xD to match the largest leaf value used by the
 * test.
 *
 * Leaf 1's eax and ebx values are also fixed. Set them to representative values
 * to help verify that the leaf 1 fixup logic doesn't change these outputs.
 */
#define	TEST_CPUID_0_EAX	0x0000000D
#define	TEST_CPUID_0_EBX	0x74737552
#define	TEST_CPUID_0_ECX	0x65646978
#define	TEST_CPUID_0_EDX	0x4F206465
#define	TEST_CPUID_1_EAX	0x00A50F00
#define	TEST_CPUID_1_EBX	0x01010800

/*
 * Leave bit 27 (OSXSAVE) cleared; it should be set if XSAVE is enabled in CR4
 * even if it wasn't set in the original explicit value.
 */
#define	TEST_CPUID_1_ECX	0xF6D83203

/*
 * Leave bit 9 (APIC enabled) set; it should be cleared if the guest disables
 * the APIC via the appropriate MSR.
 */
#define	TEST_CPUID_1_EDX	0x178BFBFF

/* The sizes needed for various XSAVE area regions. */
#define	XSAVE_AREA_SIZE_BASE	0x240
#define	XSAVE_AREA_SIZE_AVX	0x100
#define	XSAVE_AREA_SIZE_MAX	(XSAVE_AREA_SIZE_BASE + XSAVE_AREA_SIZE_AVX)

/* Advertise that x87, SSE, and AVX support are present in leaf D index 0. */
#define	TEST_CPUID_D_0_EAX	0x00000007

/* Advertise in leaf D index 1 that all state save instructions are present. */
#define	TEST_CPUID_D_1_EAX	0x0000000F

#endif /* !_CPUID_GUEST_STATE_H */
