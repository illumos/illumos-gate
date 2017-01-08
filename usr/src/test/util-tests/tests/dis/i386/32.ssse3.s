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
	pabsb		(%eax), %mm1
	pabsb		%xmm0, %xmm1
	pabsb		(%eax), %xmm1
	pabsd		%mm0, %mm1
	pabsd		(%eax), %mm1
	pabsd		%xmm0, %xmm1
	pabsd		(%eax), %xmm1
	pabsw		%mm0, %mm1
	pabsw		(%eax), %mm1
	pabsw		%xmm0, %xmm1
	pabsw		(%eax), %xmm1
	palignr		$0x23, %mm0, %mm1
	palignr		$0x23, (%eax), %mm1
	palignr		$0x23, %xmm0, %xmm1
	palignr		$0x23, (%eax), %xmm1
	phaddd		%mm0, %mm1
	phaddd		(%eax), %mm1
	phaddd		%xmm0, %xmm1
	phaddd		(%eax), %xmm1
	phaddw		%mm0, %mm1
	phaddw		(%eax), %mm1
	phaddw		%xmm0, %xmm1
	phaddw		(%eax), %xmm1
	phaddsw		%mm0, %mm1
	phaddsw		(%eax), %mm1
	phaddsw		%xmm0, %xmm1
	phaddsw		(%eax), %xmm1
	phsubd		%mm0, %mm1
	phsubd		(%eax), %mm1
	phsubd		%xmm0, %xmm1
	phsubd		(%eax), %xmm1
	phsubw		%mm0, %mm1
	phsubw		(%eax), %mm1
	phsubw		%xmm0, %xmm1
	phsubw		(%eax), %xmm1
	phsubsw		%mm0, %mm1
	phsubsw		(%eax), %mm1
	phsubsw		%xmm0, %xmm1
	phsubsw		(%eax), %xmm1
	pmaddubsw	%mm0, %mm1
	pmaddubsw	(%eax), %mm1
	pmaddubsw	%xmm0, %xmm1
	pmaddubsw	(%eax), %xmm1
	pmulhrsw	%mm0, %mm1
	pmulhrsw	(%eax), %mm1
	pmulhrsw	%xmm0, %xmm1
	pmulhrsw	(%eax), %xmm1
	pshufb		%mm0, %mm1
	pshufb		(%eax), %mm1
	pshufb		%xmm0, %xmm1
	pshufb		(%eax), %xmm1
	psignb		%mm0, %mm1
	psignb		(%eax), %mm1
	psignb		%xmm0, %xmm1
	psignb		(%eax), %xmm1
	psignd		%mm0, %mm1
	psignd		(%eax), %mm1
	psignd		%xmm0, %xmm1
	psignd		(%eax), %xmm1
	psignw		%mm0, %mm1
	psignw		(%eax), %mm1
	psignw		%xmm0, %xmm1
	psignw		(%eax), %xmm1
.size libdis_test, [.-libdis_test]
