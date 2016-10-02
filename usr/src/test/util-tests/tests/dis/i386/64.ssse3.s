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

/*
 * Test SSSE3 related instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	pabsb		%mm0, %mm1
	pabsb		(%rax), %mm1
	pabsb		%xmm0, %xmm1
	pabsb		(%rax), %xmm1
	pabsd		%mm0, %mm1
	pabsd		(%rax), %mm1
	pabsd		%xmm0, %xmm1
	pabsd		(%rax), %xmm1
	pabsw		%mm0, %mm1
	pabsw		(%rax), %mm1
	pabsw		%xmm0, %xmm1
	pabsw		(%rax), %xmm1
	palignr		$0x23, %mm0, %mm1
	palignr		$0x23, (%rax), %mm1
	palignr		$0x23, %xmm0, %xmm1
	palignr		$0x23, (%rax), %xmm1
	phaddd		%mm0, %mm1
	phaddd		(%rax), %mm1
	phaddd		%xmm0, %xmm1
	phaddd		(%rax), %xmm1
	phaddw		%mm0, %mm1
	phaddw		(%rax), %mm1
	phaddw		%xmm0, %xmm1
	phaddw		(%rax), %xmm1
	phaddsw		%mm0, %mm1
	phaddsw		(%rax), %mm1
	phaddsw		%xmm0, %xmm1
	phaddsw		(%rax), %xmm1
	phsubd		%mm0, %mm1
	phsubd		(%rax), %mm1
	phsubd		%xmm0, %xmm1
	phsubd		(%rax), %xmm1
	phsubw		%mm0, %mm1
	phsubw		(%rax), %mm1
	phsubw		%xmm0, %xmm1
	phsubw		(%rax), %xmm1
	phsubsw		%mm0, %mm1
	phsubsw		(%rax), %mm1
	phsubsw		%xmm0, %xmm1
	phsubsw		(%rax), %xmm1
	pmaddubsw	%mm0, %mm1
	pmaddubsw	(%rax), %mm1
	pmaddubsw	%xmm0, %xmm1
	pmaddubsw	(%rax), %xmm1
	pmulhrsw	%mm0, %mm1
	pmulhrsw	(%rax), %mm1
	pmulhrsw	%xmm0, %xmm1
	pmulhrsw	(%rax), %xmm1
	pshufb		%mm0, %mm1
	pshufb		(%rax), %mm1
	pshufb		%xmm0, %xmm1
	pshufb		(%rax), %xmm1
	psignb		%mm0, %mm1
	psignb		(%rax), %mm1
	psignb		%xmm0, %xmm1
	psignb		(%rax), %xmm1
	psignd		%mm0, %mm1
	psignd		(%rax), %mm1
	psignd		%xmm0, %xmm1
	psignd		(%rax), %xmm1
	psignw		%mm0, %mm1
	psignw		(%rax), %mm1
	psignw		%xmm0, %xmm1
	psignw		(%rax), %xmm1
.size libdis_test, [.-libdis_test]
