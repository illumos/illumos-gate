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
 * Test AVX related instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	vaddpd	%xmm0, %xmm1, %xmm2
	vaddpd	(%eax), %xmm3, %xmm4
	vaddpd	0x42(%ecx), %xmm5, %xmm6
	vaddpd	%ymm0, %ymm1, %ymm2
	vaddpd	(%ebx), %ymm3, %ymm4
	vaddpd	0x42(%edx), %ymm5, %ymm6

	vaddps	%xmm0, %xmm1, %xmm2
	vaddps	(%eax), %xmm3, %xmm4
	vaddps	0x42(%ecx), %xmm5, %xmm6
	vaddps	%ymm0, %ymm1, %ymm2
	vaddps	(%ebx), %ymm3, %ymm4
	vaddps	0x42(%edx), %ymm5, %ymm6

	vaddsd	%xmm0, %xmm1, %xmm2
	vaddsd	(%eax), %xmm3, %xmm4
	vaddsd	0x42(%ecx), %xmm5, %xmm6

	vaddss	%xmm0, %xmm1, %xmm2
	vaddss	(%eax), %xmm3, %xmm4
	vaddss	0x42(%ecx), %xmm5, %xmm6

	vaddsubpd	%xmm0, %xmm1, %xmm2
	vaddsubpd	(%eax), %xmm3, %xmm4
	vaddsubpd	0x42(%ecx), %xmm5, %xmm6
	vaddsubpd	%ymm0, %ymm1, %ymm2
	vaddsubpd	(%ebx), %ymm3, %ymm4
	vaddsubpd	0x42(%edx), %ymm5, %ymm6

	vaddsubps	%xmm0, %xmm1, %xmm2
	vaddsubps	(%eax), %xmm3, %xmm4
	vaddsubps	0x42(%ecx), %xmm5, %xmm6
	vaddsubps	%ymm0, %ymm1, %ymm2
	vaddsubps	(%ebx), %ymm3, %ymm4
	vaddsubps	0x42(%edx), %ymm5, %ymm6

	vaesdec	%xmm0, %xmm1, %xmm2
	vaesdec	(%eax), %xmm3, %xmm4
	vaesdec	0x42(%ecx), %xmm5, %xmm6

	vaesdeclast	%xmm0, %xmm1, %xmm2
	vaesdeclast	(%eax), %xmm3, %xmm4
	vaesdeclast	0x42(%ecx), %xmm5, %xmm6

	vaesenc	%xmm0, %xmm1, %xmm2
	vaesenc	(%eax), %xmm3, %xmm4
	vaesenc	0x42(%ecx), %xmm5, %xmm6

	vaesenclast	%xmm0, %xmm1, %xmm2
	vaesenclast	(%eax), %xmm3, %xmm4
	vaesenclast	0x42(%ecx), %xmm5, %xmm6

	vaesimc	%xmm0, %xmm1
	vaesimc	(%esi), %xmm3
	vaesimc	0x42(%edi), %xmm3

	vaeskeygenassist	$0x42, %xmm0, %xmm1
	vaeskeygenassist	$0x23, 	(%esi), %xmm3
	vaeskeygenassist	$0x42, 0x42(%edi), %xmm3

	vandnpd	%xmm0, %xmm1, %xmm2
	vandnpd	(%eax), %xmm3, %xmm4
	vandnpd	0x42(%ecx), %xmm5, %xmm6
	vandnpd	%ymm0, %ymm1, %ymm2
	vandnpd	(%ebx), %ymm3, %ymm4
	vandnpd	0x42(%edx), %ymm5, %ymm6

	vandnps	%xmm0, %xmm1, %xmm2
	vandnps	(%eax), %xmm3, %xmm4
	vandnps	0x42(%ecx), %xmm5, %xmm6
	vandnps	%ymm0, %ymm1, %ymm2
	vandnps	(%ebx), %ymm3, %ymm4
	vandnps	0x42(%edx), %ymm5, %ymm6

	vandpd	%xmm0, %xmm1, %xmm2
	vandpd	(%eax), %xmm3, %xmm4
	vandpd	0x42(%ecx), %xmm5, %xmm6
	vandpd	%ymm0, %ymm1, %ymm2
	vandpd	(%ebx), %ymm3, %ymm4
	vandpd	0x42(%edx), %ymm5, %ymm6

	vandps	%xmm0, %xmm1, %xmm2
	vandps	(%eax), %xmm3, %xmm4
	vandps	0x42(%ecx), %xmm5, %xmm6
	vandps	%ymm0, %ymm1, %ymm2
	vandps	(%ebx), %ymm3, %ymm4
	vandps	0x42(%edx), %ymm5, %ymm6

	vblendpd	$0x48, %xmm3, %xmm5, %xmm7
	vblendpd	$0x48, (%ebx), %xmm2, %xmm4
	vblendpd	$0x48, 0x8(%ebx), %xmm1, %xmm6
	vblendpd	$0x48, %ymm3, %ymm5, %ymm7
	vblendpd	$0x48, (%ebx), %ymm2, %ymm4
	vblendpd	$0x48, 0x8(%ebx), %ymm1, %ymm6

	vblendps	$0x48, %xmm3, %xmm5, %xmm7
	vblendps	$0x48, (%ebx), %xmm2, %xmm4
	vblendps	$0x48, 0x8(%ebx), %xmm1, %xmm6
	vblendps	$0x48, %ymm3, %ymm5, %ymm7
	vblendps	$0x48, (%ebx), %ymm2, %ymm4
	vblendps	$0x48, 0x8(%ebx), %ymm1, %ymm6

	vblendvpd	%xmm0, %xmm1, %xmm2, %xmm3
	vblendvpd	%xmm0, (%eax), %xmm2, %xmm3
	vblendvpd	%xmm0, 0x10(%ebx), %xmm2, %xmm3
	vblendvpd	%ymm0, %ymm1, %ymm2, %ymm3
	vblendvpd	%ymm0, (%eax), %ymm2, %ymm3
	vblendvpd	%ymm0, 0x10(%ebx), %ymm2, %ymm3

	vblendvps	%xmm0, %xmm1, %xmm2, %xmm3
	vblendvps	%xmm0, (%eax), %xmm2, %xmm3
	vblendvps	%xmm0, 0x10(%ebx), %xmm2, %xmm3
	vblendvps	%ymm0, %ymm1, %ymm2, %ymm3
	vblendvps	%ymm0, (%eax), %ymm2, %ymm3
	vblendvps	%ymm0, 0x10(%ebx), %ymm2, %ymm3

	vbroadcastf128	(%eax), %ymm0
	vbroadcastf128	0x42(%eax), %ymm0

	vbroadcastsd	(%eax), %ymm0
	vbroadcastsd	0x42(%eax), %ymm0

	vbroadcastss	(%eax), %ymm0
	vbroadcastss	0x42(%eax), %ymm0

	vcmpeq_ospd	%xmm0, %xmm1, %xmm2
	vcmpeq_ospd	(%eax), %xmm3, %xmm4
	vcmpeq_ospd	0x42(%ecx), %xmm5, %xmm6
	vcmpeq_ospd	%ymm0, %ymm1, %ymm2
	vcmpeq_ospd	(%ebx), %ymm3, %ymm4
	vcmpeq_ospd	0x42(%edx), %ymm5, %ymm6

	vcmpeq_osps	%xmm0, %xmm1, %xmm2
	vcmpeq_osps	(%eax), %xmm3, %xmm4
	vcmpeq_osps	0x42(%ecx), %xmm5, %xmm6
	vcmpeq_osps	%ymm0, %ymm1, %ymm2
	vcmpeq_osps	(%ebx), %ymm3, %ymm4
	vcmpeq_osps	0x42(%edx), %ymm5, %ymm6

	vcmpeq_ossd	%xmm0, %xmm1, %xmm2
	vcmpeq_ossd	(%eax), %xmm3, %xmm4
	vcmpeq_ossd	0x42(%ecx), %xmm5, %xmm6

	vcmpeq_osss	%xmm0, %xmm1, %xmm2
	vcmpeq_osss	(%eax), %xmm3, %xmm4
	vcmpeq_osss	0x42(%ecx), %xmm5, %xmm6

	vcmpeq_uqpd	%xmm0, %xmm1, %xmm2
	vcmpeq_uqpd	(%eax), %xmm3, %xmm4
	vcmpeq_uqpd	0x42(%ecx), %xmm5, %xmm6
	vcmpeq_uqpd	%ymm0, %ymm1, %ymm2
	vcmpeq_uqpd	(%ebx), %ymm3, %ymm4
	vcmpeq_uqpd	0x42(%edx), %ymm5, %ymm6

	vcmpeq_uqps	%xmm0, %xmm1, %xmm2
	vcmpeq_uqps	(%eax), %xmm3, %xmm4
	vcmpeq_uqps	0x42(%ecx), %xmm5, %xmm6
	vcmpeq_uqps	%ymm0, %ymm1, %ymm2
	vcmpeq_uqps	(%ebx), %ymm3, %ymm4
	vcmpeq_uqps	0x42(%edx), %ymm5, %ymm6

	vcmpeq_uqsd	%xmm0, %xmm1, %xmm2
	vcmpeq_uqsd	(%eax), %xmm3, %xmm4
	vcmpeq_uqsd	0x42(%ecx), %xmm5, %xmm6

	vcmpeq_uqss	%xmm0, %xmm1, %xmm2
	vcmpeq_uqss	(%eax), %xmm3, %xmm4
	vcmpeq_uqss	0x42(%ecx), %xmm5, %xmm6

	vcmpeq_uspd	%xmm0, %xmm1, %xmm2
	vcmpeq_uspd	(%eax), %xmm3, %xmm4
	vcmpeq_uspd	0x42(%ecx), %xmm5, %xmm6
	vcmpeq_uspd	%ymm0, %ymm1, %ymm2
	vcmpeq_uspd	(%ebx), %ymm3, %ymm4
	vcmpeq_uspd	0x42(%edx), %ymm5, %ymm6

	vcmpeq_usps	%xmm0, %xmm1, %xmm2
	vcmpeq_usps	(%eax), %xmm3, %xmm4
	vcmpeq_usps	0x42(%ecx), %xmm5, %xmm6
	vcmpeq_usps	%ymm0, %ymm1, %ymm2
	vcmpeq_usps	(%ebx), %ymm3, %ymm4
	vcmpeq_usps	0x42(%edx), %ymm5, %ymm6

	vcmpeq_ussd	%xmm0, %xmm1, %xmm2
	vcmpeq_ussd	(%eax), %xmm3, %xmm4
	vcmpeq_ussd	0x42(%ecx), %xmm5, %xmm6

	vcmpeq_usss	%xmm0, %xmm1, %xmm2
	vcmpeq_usss	(%eax), %xmm3, %xmm4
	vcmpeq_usss	0x42(%ecx), %xmm5, %xmm6

	vcmpeqpd	%xmm0, %xmm1, %xmm2
	vcmpeqpd	(%eax), %xmm3, %xmm4
	vcmpeqpd	0x42(%ecx), %xmm5, %xmm6
	vcmpeqpd	%ymm0, %ymm1, %ymm2
	vcmpeqpd	(%ebx), %ymm3, %ymm4
	vcmpeqpd	0x42(%edx), %ymm5, %ymm6

	vcmpeqps	%xmm0, %xmm1, %xmm2
	vcmpeqps	(%eax), %xmm3, %xmm4
	vcmpeqps	0x42(%ecx), %xmm5, %xmm6
	vcmpeqps	%ymm0, %ymm1, %ymm2
	vcmpeqps	(%ebx), %ymm3, %ymm4
	vcmpeqps	0x42(%edx), %ymm5, %ymm6

	vcmpeqsd	%xmm0, %xmm1, %xmm2
	vcmpeqsd	(%eax), %xmm3, %xmm4
	vcmpeqsd	0x42(%ecx), %xmm5, %xmm6

	vcmpeqss	%xmm0, %xmm1, %xmm2
	vcmpeqss	(%eax), %xmm3, %xmm4
	vcmpeqss	0x42(%ecx), %xmm5, %xmm6

	vcmpfalse_ospd	%xmm0, %xmm1, %xmm2
	vcmpfalse_ospd	(%eax), %xmm3, %xmm4
	vcmpfalse_ospd	0x42(%ecx), %xmm5, %xmm6
	vcmpfalse_ospd	%ymm0, %ymm1, %ymm2
	vcmpfalse_ospd	(%ebx), %ymm3, %ymm4
	vcmpfalse_ospd	0x42(%edx), %ymm5, %ymm6

	vcmpfalse_osps	%xmm0, %xmm1, %xmm2
	vcmpfalse_osps	(%eax), %xmm3, %xmm4
	vcmpfalse_osps	0x42(%ecx), %xmm5, %xmm6
	vcmpfalse_osps	%ymm0, %ymm1, %ymm2
	vcmpfalse_osps	(%ebx), %ymm3, %ymm4
	vcmpfalse_osps	0x42(%edx), %ymm5, %ymm6

	vcmpfalse_ossd	%xmm0, %xmm1, %xmm2
	vcmpfalse_ossd	(%eax), %xmm3, %xmm4
	vcmpfalse_ossd	0x42(%ecx), %xmm5, %xmm6

	vcmpfalse_osss	%xmm0, %xmm1, %xmm2
	vcmpfalse_osss	(%eax), %xmm3, %xmm4
	vcmpfalse_osss	0x42(%ecx), %xmm5, %xmm6

	vcmpfalsepd	%xmm0, %xmm1, %xmm2
	vcmpfalsepd	(%eax), %xmm3, %xmm4
	vcmpfalsepd	0x42(%ecx), %xmm5, %xmm6
	vcmpfalsepd	%ymm0, %ymm1, %ymm2
	vcmpfalsepd	(%ebx), %ymm3, %ymm4
	vcmpfalsepd	0x42(%edx), %ymm5, %ymm6

	vcmpfalseps	%xmm0, %xmm1, %xmm2
	vcmpfalseps	(%eax), %xmm3, %xmm4
	vcmpfalseps	0x42(%ecx), %xmm5, %xmm6
	vcmpfalseps	%ymm0, %ymm1, %ymm2
	vcmpfalseps	(%ebx), %ymm3, %ymm4
	vcmpfalseps	0x42(%edx), %ymm5, %ymm6

	vcmpfalsesd	%xmm0, %xmm1, %xmm2
	vcmpfalsesd	(%eax), %xmm3, %xmm4
	vcmpfalsesd	0x42(%ecx), %xmm5, %xmm6

	vcmpfalsess	%xmm0, %xmm1, %xmm2
	vcmpfalsess	(%eax), %xmm3, %xmm4
	vcmpfalsess	0x42(%ecx), %xmm5, %xmm6

	vcmpge_oqpd	%xmm0, %xmm1, %xmm2
	vcmpge_oqpd	(%eax), %xmm3, %xmm4
	vcmpge_oqpd	0x42(%ecx), %xmm5, %xmm6
	vcmpge_oqpd	%ymm0, %ymm1, %ymm2
	vcmpge_oqpd	(%ebx), %ymm3, %ymm4
	vcmpge_oqpd	0x42(%edx), %ymm5, %ymm6

	vcmpge_oqps	%xmm0, %xmm1, %xmm2
	vcmpge_oqps	(%eax), %xmm3, %xmm4
	vcmpge_oqps	0x42(%ecx), %xmm5, %xmm6
	vcmpge_oqps	%ymm0, %ymm1, %ymm2
	vcmpge_oqps	(%ebx), %ymm3, %ymm4
	vcmpge_oqps	0x42(%edx), %ymm5, %ymm6

	vcmpge_oqsd	%xmm0, %xmm1, %xmm2
	vcmpge_oqsd	(%eax), %xmm3, %xmm4
	vcmpge_oqsd	0x42(%ecx), %xmm5, %xmm6

	vcmpge_oqss	%xmm0, %xmm1, %xmm2
	vcmpge_oqss	(%eax), %xmm3, %xmm4
	vcmpge_oqss	0x42(%ecx), %xmm5, %xmm6

	vcmpgepd	%xmm0, %xmm1, %xmm2
	vcmpgepd	(%eax), %xmm3, %xmm4
	vcmpgepd	0x42(%ecx), %xmm5, %xmm6
	vcmpgepd	%ymm0, %ymm1, %ymm2
	vcmpgepd	(%ebx), %ymm3, %ymm4
	vcmpgepd	0x42(%edx), %ymm5, %ymm6

	vcmpgeps	%xmm0, %xmm1, %xmm2
	vcmpgeps	(%eax), %xmm3, %xmm4
	vcmpgeps	0x42(%ecx), %xmm5, %xmm6
	vcmpgeps	%ymm0, %ymm1, %ymm2
	vcmpgeps	(%ebx), %ymm3, %ymm4
	vcmpgeps	0x42(%edx), %ymm5, %ymm6

	vcmpgesd	%xmm0, %xmm1, %xmm2
	vcmpgesd	(%eax), %xmm3, %xmm4
	vcmpgesd	0x42(%ecx), %xmm5, %xmm6

	vcmpgess	%xmm0, %xmm1, %xmm2
	vcmpgess	(%eax), %xmm3, %xmm4
	vcmpgess	0x42(%ecx), %xmm5, %xmm6

	vcmpgt_oqpd	%xmm0, %xmm1, %xmm2
	vcmpgt_oqpd	(%eax), %xmm3, %xmm4
	vcmpgt_oqpd	0x42(%ecx), %xmm5, %xmm6
	vcmpgt_oqpd	%ymm0, %ymm1, %ymm2
	vcmpgt_oqpd	(%ebx), %ymm3, %ymm4
	vcmpgt_oqpd	0x42(%edx), %ymm5, %ymm6

	vcmpgt_oqps	%xmm0, %xmm1, %xmm2
	vcmpgt_oqps	(%eax), %xmm3, %xmm4
	vcmpgt_oqps	0x42(%ecx), %xmm5, %xmm6
	vcmpgt_oqps	%ymm0, %ymm1, %ymm2
	vcmpgt_oqps	(%ebx), %ymm3, %ymm4
	vcmpgt_oqps	0x42(%edx), %ymm5, %ymm6

	vcmpgt_oqsd	%xmm0, %xmm1, %xmm2
	vcmpgt_oqsd	(%eax), %xmm3, %xmm4
	vcmpgt_oqsd	0x42(%ecx), %xmm5, %xmm6

	vcmpgt_oqss	%xmm0, %xmm1, %xmm2
	vcmpgt_oqss	(%eax), %xmm3, %xmm4
	vcmpgt_oqss	0x42(%ecx), %xmm5, %xmm6

	vcmpgtpd	%xmm0, %xmm1, %xmm2
	vcmpgtpd	(%eax), %xmm3, %xmm4
	vcmpgtpd	0x42(%ecx), %xmm5, %xmm6
	vcmpgtpd	%ymm0, %ymm1, %ymm2
	vcmpgtpd	(%ebx), %ymm3, %ymm4
	vcmpgtpd	0x42(%edx), %ymm5, %ymm6

	vcmpgtps	%xmm0, %xmm1, %xmm2
	vcmpgtps	(%eax), %xmm3, %xmm4
	vcmpgtps	0x42(%ecx), %xmm5, %xmm6
	vcmpgtps	%ymm0, %ymm1, %ymm2
	vcmpgtps	(%ebx), %ymm3, %ymm4
	vcmpgtps	0x42(%edx), %ymm5, %ymm6

	vcmpgtsd	%xmm0, %xmm1, %xmm2
	vcmpgtsd	(%eax), %xmm3, %xmm4
	vcmpgtsd	0x42(%ecx), %xmm5, %xmm6

	vcmpgtss	%xmm0, %xmm1, %xmm2
	vcmpgtss	(%eax), %xmm3, %xmm4
	vcmpgtss	0x42(%ecx), %xmm5, %xmm6

	vcmple_oqpd	%xmm0, %xmm1, %xmm2
	vcmple_oqpd	(%eax), %xmm3, %xmm4
	vcmple_oqpd	0x42(%ecx), %xmm5, %xmm6
	vcmple_oqpd	%ymm0, %ymm1, %ymm2
	vcmple_oqpd	(%ebx), %ymm3, %ymm4
	vcmple_oqpd	0x42(%edx), %ymm5, %ymm6

	vcmple_oqps	%xmm0, %xmm1, %xmm2
	vcmple_oqps	(%eax), %xmm3, %xmm4
	vcmple_oqps	0x42(%ecx), %xmm5, %xmm6
	vcmple_oqps	%ymm0, %ymm1, %ymm2
	vcmple_oqps	(%ebx), %ymm3, %ymm4
	vcmple_oqps	0x42(%edx), %ymm5, %ymm6

	vcmple_oqsd	%xmm0, %xmm1, %xmm2
	vcmple_oqsd	(%eax), %xmm3, %xmm4
	vcmple_oqsd	0x42(%ecx), %xmm5, %xmm6

	vcmple_oqss	%xmm0, %xmm1, %xmm2
	vcmple_oqss	(%eax), %xmm3, %xmm4
	vcmple_oqss	0x42(%ecx), %xmm5, %xmm6

	vcmplepd	%xmm0, %xmm1, %xmm2
	vcmplepd	(%eax), %xmm3, %xmm4
	vcmplepd	0x42(%ecx), %xmm5, %xmm6
	vcmplepd	%ymm0, %ymm1, %ymm2
	vcmplepd	(%ebx), %ymm3, %ymm4
	vcmplepd	0x42(%edx), %ymm5, %ymm6

	vcmpleps	%xmm0, %xmm1, %xmm2
	vcmpleps	(%eax), %xmm3, %xmm4
	vcmpleps	0x42(%ecx), %xmm5, %xmm6
	vcmpleps	%ymm0, %ymm1, %ymm2
	vcmpleps	(%ebx), %ymm3, %ymm4
	vcmpleps	0x42(%edx), %ymm5, %ymm6

	vcmplesd	%xmm0, %xmm1, %xmm2
	vcmplesd	(%eax), %xmm3, %xmm4
	vcmplesd	0x42(%ecx), %xmm5, %xmm6

	vcmpless	%xmm0, %xmm1, %xmm2
	vcmpless	(%eax), %xmm3, %xmm4
	vcmpless	0x42(%ecx), %xmm5, %xmm6

	vcmplt_oqpd	%xmm0, %xmm1, %xmm2
	vcmplt_oqpd	(%eax), %xmm3, %xmm4
	vcmplt_oqpd	0x42(%ecx), %xmm5, %xmm6
	vcmplt_oqpd	%ymm0, %ymm1, %ymm2
	vcmplt_oqpd	(%ebx), %ymm3, %ymm4
	vcmplt_oqpd	0x42(%edx), %ymm5, %ymm6

	vcmplt_oqps	%xmm0, %xmm1, %xmm2
	vcmplt_oqps	(%eax), %xmm3, %xmm4
	vcmplt_oqps	0x42(%ecx), %xmm5, %xmm6
	vcmplt_oqps	%ymm0, %ymm1, %ymm2
	vcmplt_oqps	(%ebx), %ymm3, %ymm4
	vcmplt_oqps	0x42(%edx), %ymm5, %ymm6

	vcmplt_oqsd	%xmm0, %xmm1, %xmm2
	vcmplt_oqsd	(%eax), %xmm3, %xmm4
	vcmplt_oqsd	0x42(%ecx), %xmm5, %xmm6

	vcmplt_oqss	%xmm0, %xmm1, %xmm2
	vcmplt_oqss	(%eax), %xmm3, %xmm4
	vcmplt_oqss	0x42(%ecx), %xmm5, %xmm6

	vcmpltpd	%xmm0, %xmm1, %xmm2
	vcmpltpd	(%eax), %xmm3, %xmm4
	vcmpltpd	0x42(%ecx), %xmm5, %xmm6
	vcmpltpd	%ymm0, %ymm1, %ymm2
	vcmpltpd	(%ebx), %ymm3, %ymm4
	vcmpltpd	0x42(%edx), %ymm5, %ymm6

	vcmpltps	%xmm0, %xmm1, %xmm2
	vcmpltps	(%eax), %xmm3, %xmm4
	vcmpltps	0x42(%ecx), %xmm5, %xmm6
	vcmpltps	%ymm0, %ymm1, %ymm2
	vcmpltps	(%ebx), %ymm3, %ymm4
	vcmpltps	0x42(%edx), %ymm5, %ymm6

	vcmpltsd	%xmm0, %xmm1, %xmm2
	vcmpltsd	(%eax), %xmm3, %xmm4
	vcmpltsd	0x42(%ecx), %xmm5, %xmm6

	vcmpltss	%xmm0, %xmm1, %xmm2
	vcmpltss	(%eax), %xmm3, %xmm4
	vcmpltss	0x42(%ecx), %xmm5, %xmm6

	vcmpneq_oqpd	%xmm0, %xmm1, %xmm2
	vcmpneq_oqpd	(%eax), %xmm3, %xmm4
	vcmpneq_oqpd	0x42(%ecx), %xmm5, %xmm6
	vcmpneq_oqpd	%ymm0, %ymm1, %ymm2
	vcmpneq_oqpd	(%ebx), %ymm3, %ymm4
	vcmpneq_oqpd	0x42(%edx), %ymm5, %ymm6

	vcmpneq_oqps	%xmm0, %xmm1, %xmm2
	vcmpneq_oqps	(%eax), %xmm3, %xmm4
	vcmpneq_oqps	0x42(%ecx), %xmm5, %xmm6
	vcmpneq_oqps	%ymm0, %ymm1, %ymm2
	vcmpneq_oqps	(%ebx), %ymm3, %ymm4
	vcmpneq_oqps	0x42(%edx), %ymm5, %ymm6

	vcmpneq_oqsd	%xmm0, %xmm1, %xmm2
	vcmpneq_oqsd	(%eax), %xmm3, %xmm4
	vcmpneq_oqsd	0x42(%ecx), %xmm5, %xmm6

	vcmpneq_oqss	%xmm0, %xmm1, %xmm2
	vcmpneq_oqss	(%eax), %xmm3, %xmm4
	vcmpneq_oqss	0x42(%ecx), %xmm5, %xmm6

	vcmpneq_ospd	%xmm0, %xmm1, %xmm2
	vcmpneq_ospd	(%eax), %xmm3, %xmm4
	vcmpneq_ospd	0x42(%ecx), %xmm5, %xmm6
	vcmpneq_ospd	%ymm0, %ymm1, %ymm2
	vcmpneq_ospd	(%ebx), %ymm3, %ymm4
	vcmpneq_ospd	0x42(%edx), %ymm5, %ymm6

	vcmpneq_osps	%xmm0, %xmm1, %xmm2
	vcmpneq_osps	(%eax), %xmm3, %xmm4
	vcmpneq_osps	0x42(%ecx), %xmm5, %xmm6
	vcmpneq_osps	%ymm0, %ymm1, %ymm2
	vcmpneq_osps	(%ebx), %ymm3, %ymm4
	vcmpneq_osps	0x42(%edx), %ymm5, %ymm6

	vcmpneq_ossd	%xmm0, %xmm1, %xmm2
	vcmpneq_ossd	(%eax), %xmm3, %xmm4
	vcmpneq_ossd	0x42(%ecx), %xmm5, %xmm6

	vcmpneq_osss	%xmm0, %xmm1, %xmm2
	vcmpneq_osss	(%eax), %xmm3, %xmm4
	vcmpneq_osss	0x42(%ecx), %xmm5, %xmm6

	vcmpneq_uspd	%xmm0, %xmm1, %xmm2
	vcmpneq_uspd	(%eax), %xmm3, %xmm4
	vcmpneq_uspd	0x42(%ecx), %xmm5, %xmm6
	vcmpneq_uspd	%ymm0, %ymm1, %ymm2
	vcmpneq_uspd	(%ebx), %ymm3, %ymm4
	vcmpneq_uspd	0x42(%edx), %ymm5, %ymm6

	vcmpneq_usps	%xmm0, %xmm1, %xmm2
	vcmpneq_usps	(%eax), %xmm3, %xmm4
	vcmpneq_usps	0x42(%ecx), %xmm5, %xmm6
	vcmpneq_usps	%ymm0, %ymm1, %ymm2
	vcmpneq_usps	(%ebx), %ymm3, %ymm4
	vcmpneq_usps	0x42(%edx), %ymm5, %ymm6

	vcmpneq_ussd	%xmm0, %xmm1, %xmm2
	vcmpneq_ussd	(%eax), %xmm3, %xmm4
	vcmpneq_ussd	0x42(%ecx), %xmm5, %xmm6

	vcmpneq_usss	%xmm0, %xmm1, %xmm2
	vcmpneq_usss	(%eax), %xmm3, %xmm4
	vcmpneq_usss	0x42(%ecx), %xmm5, %xmm6

	vcmpneqpd	%xmm0, %xmm1, %xmm2
	vcmpneqpd	(%eax), %xmm3, %xmm4
	vcmpneqpd	0x42(%ecx), %xmm5, %xmm6
	vcmpneqpd	%ymm0, %ymm1, %ymm2
	vcmpneqpd	(%ebx), %ymm3, %ymm4
	vcmpneqpd	0x42(%edx), %ymm5, %ymm6

	vcmpneqps	%xmm0, %xmm1, %xmm2
	vcmpneqps	(%eax), %xmm3, %xmm4
	vcmpneqps	0x42(%ecx), %xmm5, %xmm6
	vcmpneqps	%ymm0, %ymm1, %ymm2
	vcmpneqps	(%ebx), %ymm3, %ymm4
	vcmpneqps	0x42(%edx), %ymm5, %ymm6

	vcmpneqsd	%xmm0, %xmm1, %xmm2
	vcmpneqsd	(%eax), %xmm3, %xmm4
	vcmpneqsd	0x42(%ecx), %xmm5, %xmm6

	vcmpneqss	%xmm0, %xmm1, %xmm2
	vcmpneqss	(%eax), %xmm3, %xmm4
	vcmpneqss	0x42(%ecx), %xmm5, %xmm6

	vcmpnge_uqpd	%xmm0, %xmm1, %xmm2
	vcmpnge_uqpd	(%eax), %xmm3, %xmm4
	vcmpnge_uqpd	0x42(%ecx), %xmm5, %xmm6
	vcmpnge_uqpd	%ymm0, %ymm1, %ymm2
	vcmpnge_uqpd	(%ebx), %ymm3, %ymm4
	vcmpnge_uqpd	0x42(%edx), %ymm5, %ymm6

	vcmpnge_uqps	%xmm0, %xmm1, %xmm2
	vcmpnge_uqps	(%eax), %xmm3, %xmm4
	vcmpnge_uqps	0x42(%ecx), %xmm5, %xmm6
	vcmpnge_uqps	%ymm0, %ymm1, %ymm2
	vcmpnge_uqps	(%ebx), %ymm3, %ymm4
	vcmpnge_uqps	0x42(%edx), %ymm5, %ymm6

	vcmpnge_uqsd	%xmm0, %xmm1, %xmm2
	vcmpnge_uqsd	(%eax), %xmm3, %xmm4
	vcmpnge_uqsd	0x42(%ecx), %xmm5, %xmm6

	vcmpnge_uqss	%xmm0, %xmm1, %xmm2
	vcmpnge_uqss	(%eax), %xmm3, %xmm4
	vcmpnge_uqss	0x42(%ecx), %xmm5, %xmm6

	vcmpngepd	%xmm0, %xmm1, %xmm2
	vcmpngepd	(%eax), %xmm3, %xmm4
	vcmpngepd	0x42(%ecx), %xmm5, %xmm6
	vcmpngepd	%ymm0, %ymm1, %ymm2
	vcmpngepd	(%ebx), %ymm3, %ymm4
	vcmpngepd	0x42(%edx), %ymm5, %ymm6

	vcmpngeps	%xmm0, %xmm1, %xmm2
	vcmpngeps	(%eax), %xmm3, %xmm4
	vcmpngeps	0x42(%ecx), %xmm5, %xmm6
	vcmpngeps	%ymm0, %ymm1, %ymm2
	vcmpngeps	(%ebx), %ymm3, %ymm4
	vcmpngeps	0x42(%edx), %ymm5, %ymm6

	vcmpngesd	%xmm0, %xmm1, %xmm2
	vcmpngesd	(%eax), %xmm3, %xmm4
	vcmpngesd	0x42(%ecx), %xmm5, %xmm6

	vcmpngess	%xmm0, %xmm1, %xmm2
	vcmpngess	(%eax), %xmm3, %xmm4
	vcmpngess	0x42(%ecx), %xmm5, %xmm6

	vcmpngt_uqpd	%xmm0, %xmm1, %xmm2
	vcmpngt_uqpd	(%eax), %xmm3, %xmm4
	vcmpngt_uqpd	0x42(%ecx), %xmm5, %xmm6
	vcmpngt_uqpd	%ymm0, %ymm1, %ymm2
	vcmpngt_uqpd	(%ebx), %ymm3, %ymm4
	vcmpngt_uqpd	0x42(%edx), %ymm5, %ymm6

	vcmpngt_uqps	%xmm0, %xmm1, %xmm2
	vcmpngt_uqps	(%eax), %xmm3, %xmm4
	vcmpngt_uqps	0x42(%ecx), %xmm5, %xmm6
	vcmpngt_uqps	%ymm0, %ymm1, %ymm2
	vcmpngt_uqps	(%ebx), %ymm3, %ymm4
	vcmpngt_uqps	0x42(%edx), %ymm5, %ymm6

	vcmpngt_uqsd	%xmm0, %xmm1, %xmm2
	vcmpngt_uqsd	(%eax), %xmm3, %xmm4
	vcmpngt_uqsd	0x42(%ecx), %xmm5, %xmm6

	vcmpngt_uqss	%xmm0, %xmm1, %xmm2
	vcmpngt_uqss	(%eax), %xmm3, %xmm4
	vcmpngt_uqss	0x42(%ecx), %xmm5, %xmm6

	vcmpngtpd	%xmm0, %xmm1, %xmm2
	vcmpngtpd	(%eax), %xmm3, %xmm4
	vcmpngtpd	0x42(%ecx), %xmm5, %xmm6
	vcmpngtpd	%ymm0, %ymm1, %ymm2
	vcmpngtpd	(%ebx), %ymm3, %ymm4
	vcmpngtpd	0x42(%edx), %ymm5, %ymm6

	vcmpngtps	%xmm0, %xmm1, %xmm2
	vcmpngtps	(%eax), %xmm3, %xmm4
	vcmpngtps	0x42(%ecx), %xmm5, %xmm6
	vcmpngtps	%ymm0, %ymm1, %ymm2
	vcmpngtps	(%ebx), %ymm3, %ymm4
	vcmpngtps	0x42(%edx), %ymm5, %ymm6

	vcmpngtsd	%xmm0, %xmm1, %xmm2
	vcmpngtsd	(%eax), %xmm3, %xmm4
	vcmpngtsd	0x42(%ecx), %xmm5, %xmm6

	vcmpngtss	%xmm0, %xmm1, %xmm2
	vcmpngtss	(%eax), %xmm3, %xmm4
	vcmpngtss	0x42(%ecx), %xmm5, %xmm6

	vcmpnle_uqpd	%xmm0, %xmm1, %xmm2
	vcmpnle_uqpd	(%eax), %xmm3, %xmm4
	vcmpnle_uqpd	0x42(%ecx), %xmm5, %xmm6
	vcmpnle_uqpd	%ymm0, %ymm1, %ymm2
	vcmpnle_uqpd	(%ebx), %ymm3, %ymm4
	vcmpnle_uqpd	0x42(%edx), %ymm5, %ymm6

	vcmpnle_uqps	%xmm0, %xmm1, %xmm2
	vcmpnle_uqps	(%eax), %xmm3, %xmm4
	vcmpnle_uqps	0x42(%ecx), %xmm5, %xmm6
	vcmpnle_uqps	%ymm0, %ymm1, %ymm2
	vcmpnle_uqps	(%ebx), %ymm3, %ymm4
	vcmpnle_uqps	0x42(%edx), %ymm5, %ymm6

	vcmpnle_uqsd	%xmm0, %xmm1, %xmm2
	vcmpnle_uqsd	(%eax), %xmm3, %xmm4
	vcmpnle_uqsd	0x42(%ecx), %xmm5, %xmm6

	vcmpnle_uqss	%xmm0, %xmm1, %xmm2
	vcmpnle_uqss	(%eax), %xmm3, %xmm4
	vcmpnle_uqss	0x42(%ecx), %xmm5, %xmm6

	vcmpnlepd	%xmm0, %xmm1, %xmm2
	vcmpnlepd	(%eax), %xmm3, %xmm4
	vcmpnlepd	0x42(%ecx), %xmm5, %xmm6
	vcmpnlepd	%ymm0, %ymm1, %ymm2
	vcmpnlepd	(%ebx), %ymm3, %ymm4
	vcmpnlepd	0x42(%edx), %ymm5, %ymm6

	vcmpnleps	%xmm0, %xmm1, %xmm2
	vcmpnleps	(%eax), %xmm3, %xmm4
	vcmpnleps	0x42(%ecx), %xmm5, %xmm6
	vcmpnleps	%ymm0, %ymm1, %ymm2
	vcmpnleps	(%ebx), %ymm3, %ymm4
	vcmpnleps	0x42(%edx), %ymm5, %ymm6

	vcmpnlesd	%xmm0, %xmm1, %xmm2
	vcmpnlesd	(%eax), %xmm3, %xmm4
	vcmpnlesd	0x42(%ecx), %xmm5, %xmm6

	vcmpnless	%xmm0, %xmm1, %xmm2
	vcmpnless	(%eax), %xmm3, %xmm4
	vcmpnless	0x42(%ecx), %xmm5, %xmm6

	vcmpnlt_uqpd	%xmm0, %xmm1, %xmm2
	vcmpnlt_uqpd	(%eax), %xmm3, %xmm4
	vcmpnlt_uqpd	0x42(%ecx), %xmm5, %xmm6
	vcmpnlt_uqpd	%ymm0, %ymm1, %ymm2
	vcmpnlt_uqpd	(%ebx), %ymm3, %ymm4
	vcmpnlt_uqpd	0x42(%edx), %ymm5, %ymm6

	vcmpnlt_uqps	%xmm0, %xmm1, %xmm2
	vcmpnlt_uqps	(%eax), %xmm3, %xmm4
	vcmpnlt_uqps	0x42(%ecx), %xmm5, %xmm6
	vcmpnlt_uqps	%ymm0, %ymm1, %ymm2
	vcmpnlt_uqps	(%ebx), %ymm3, %ymm4
	vcmpnlt_uqps	0x42(%edx), %ymm5, %ymm6

	vcmpnlt_uqsd	%xmm0, %xmm1, %xmm2
	vcmpnlt_uqsd	(%eax), %xmm3, %xmm4
	vcmpnlt_uqsd	0x42(%ecx), %xmm5, %xmm6

	vcmpnlt_uqss	%xmm0, %xmm1, %xmm2
	vcmpnlt_uqss	(%eax), %xmm3, %xmm4
	vcmpnlt_uqss	0x42(%ecx), %xmm5, %xmm6

	vcmpnltpd	%xmm0, %xmm1, %xmm2
	vcmpnltpd	(%eax), %xmm3, %xmm4
	vcmpnltpd	0x42(%ecx), %xmm5, %xmm6
	vcmpnltpd	%ymm0, %ymm1, %ymm2
	vcmpnltpd	(%ebx), %ymm3, %ymm4
	vcmpnltpd	0x42(%edx), %ymm5, %ymm6

	vcmpnltps	%xmm0, %xmm1, %xmm2
	vcmpnltps	(%eax), %xmm3, %xmm4
	vcmpnltps	0x42(%ecx), %xmm5, %xmm6
	vcmpnltps	%ymm0, %ymm1, %ymm2
	vcmpnltps	(%ebx), %ymm3, %ymm4
	vcmpnltps	0x42(%edx), %ymm5, %ymm6

	vcmpnltsd	%xmm0, %xmm1, %xmm2
	vcmpnltsd	(%eax), %xmm3, %xmm4
	vcmpnltsd	0x42(%ecx), %xmm5, %xmm6

	vcmpnltss	%xmm0, %xmm1, %xmm2
	vcmpnltss	(%eax), %xmm3, %xmm4
	vcmpnltss	0x42(%ecx), %xmm5, %xmm6

	vcmpord_spd	%xmm0, %xmm1, %xmm2
	vcmpord_spd	(%eax), %xmm3, %xmm4
	vcmpord_spd	0x42(%ecx), %xmm5, %xmm6
	vcmpord_spd	%ymm0, %ymm1, %ymm2
	vcmpord_spd	(%ebx), %ymm3, %ymm4
	vcmpord_spd	0x42(%edx), %ymm5, %ymm6

	vcmpord_sps	%xmm0, %xmm1, %xmm2
	vcmpord_sps	(%eax), %xmm3, %xmm4
	vcmpord_sps	0x42(%ecx), %xmm5, %xmm6
	vcmpord_sps	%ymm0, %ymm1, %ymm2
	vcmpord_sps	(%ebx), %ymm3, %ymm4
	vcmpord_sps	0x42(%edx), %ymm5, %ymm6

	vcmpord_ssd	%xmm0, %xmm1, %xmm2
	vcmpord_ssd	(%eax), %xmm3, %xmm4
	vcmpord_ssd	0x42(%ecx), %xmm5, %xmm6

	vcmpord_sss	%xmm0, %xmm1, %xmm2
	vcmpord_sss	(%eax), %xmm3, %xmm4
	vcmpord_sss	0x42(%ecx), %xmm5, %xmm6

	vcmpordpd	%xmm0, %xmm1, %xmm2
	vcmpordpd	(%eax), %xmm3, %xmm4
	vcmpordpd	0x42(%ecx), %xmm5, %xmm6
	vcmpordpd	%ymm0, %ymm1, %ymm2
	vcmpordpd	(%ebx), %ymm3, %ymm4
	vcmpordpd	0x42(%edx), %ymm5, %ymm6

	vcmpordps	%xmm0, %xmm1, %xmm2
	vcmpordps	(%eax), %xmm3, %xmm4
	vcmpordps	0x42(%ecx), %xmm5, %xmm6
	vcmpordps	%ymm0, %ymm1, %ymm2
	vcmpordps	(%ebx), %ymm3, %ymm4
	vcmpordps	0x42(%edx), %ymm5, %ymm6

	vcmpordsd	%xmm0, %xmm1, %xmm2
	vcmpordsd	(%eax), %xmm3, %xmm4
	vcmpordsd	0x42(%ecx), %xmm5, %xmm6

	vcmpordss	%xmm0, %xmm1, %xmm2
	vcmpordss	(%eax), %xmm3, %xmm4
	vcmpordss	0x42(%ecx), %xmm5, %xmm6

	vcmppd	$0x48, %xmm3, %xmm5, %xmm7
	vcmppd	$0x48, (%ebx), %xmm2, %xmm4
	vcmppd	$0x48, 0x8(%ebx), %xmm1, %xmm6
	vcmppd	$0x48, %ymm3, %ymm5, %ymm7
	vcmppd	$0x48, (%ebx), %ymm2, %ymm4
	vcmppd	$0x48, 0x8(%ebx), %ymm1, %ymm6

	vcmpps	$0x48, %xmm3, %xmm5, %xmm7
	vcmpps	$0x48, (%ebx), %xmm2, %xmm4
	vcmpps	$0x48, 0x8(%ebx), %xmm1, %xmm6
	vcmpps	$0x48, %ymm3, %ymm5, %ymm7
	vcmpps	$0x48, (%ebx), %ymm2, %ymm4
	vcmpps	$0x48, 0x8(%ebx), %ymm1, %ymm6

	vcmpsd	$0x48, %xmm3, %xmm5, %xmm7
	vcmpsd	$0x48, (%ebx), %xmm2, %xmm4
	vcmpsd	$0x48, 0x8(%ebx), %xmm1, %xmm6

	vcmpss	$0x48, %xmm3, %xmm5, %xmm7
	vcmpss	$0x48, (%ebx), %xmm2, %xmm4
	vcmpss	$0x48, 0x8(%ebx), %xmm1, %xmm6

	vcmptrue_uspd	%xmm0, %xmm1, %xmm2
	vcmptrue_uspd	(%eax), %xmm3, %xmm4
	vcmptrue_uspd	0x42(%ecx), %xmm5, %xmm6
	vcmptrue_uspd	%ymm0, %ymm1, %ymm2
	vcmptrue_uspd	(%ebx), %ymm3, %ymm4
	vcmptrue_uspd	0x42(%edx), %ymm5, %ymm6

	vcmptrue_usps	%xmm0, %xmm1, %xmm2
	vcmptrue_usps	(%eax), %xmm3, %xmm4
	vcmptrue_usps	0x42(%ecx), %xmm5, %xmm6
	vcmptrue_usps	%ymm0, %ymm1, %ymm2
	vcmptrue_usps	(%ebx), %ymm3, %ymm4
	vcmptrue_usps	0x42(%edx), %ymm5, %ymm6

	vcmptrue_ussd	%xmm0, %xmm1, %xmm2
	vcmptrue_ussd	(%eax), %xmm3, %xmm4
	vcmptrue_ussd	0x42(%ecx), %xmm5, %xmm6

	vcmptrue_usss	%xmm0, %xmm1, %xmm2
	vcmptrue_usss	(%eax), %xmm3, %xmm4
	vcmptrue_usss	0x42(%ecx), %xmm5, %xmm6

	vcmptruepd	%xmm0, %xmm1, %xmm2
	vcmptruepd	(%eax), %xmm3, %xmm4
	vcmptruepd	0x42(%ecx), %xmm5, %xmm6
	vcmptruepd	%ymm0, %ymm1, %ymm2
	vcmptruepd	(%ebx), %ymm3, %ymm4
	vcmptruepd	0x42(%edx), %ymm5, %ymm6

	vcmptrueps	%xmm0, %xmm1, %xmm2
	vcmptrueps	(%eax), %xmm3, %xmm4
	vcmptrueps	0x42(%ecx), %xmm5, %xmm6
	vcmptrueps	%ymm0, %ymm1, %ymm2
	vcmptrueps	(%ebx), %ymm3, %ymm4
	vcmptrueps	0x42(%edx), %ymm5, %ymm6

	vcmptruesd	%xmm0, %xmm1, %xmm2
	vcmptruesd	(%eax), %xmm3, %xmm4
	vcmptruesd	0x42(%ecx), %xmm5, %xmm6

	vcmptruess	%xmm0, %xmm1, %xmm2
	vcmptruess	(%eax), %xmm3, %xmm4
	vcmptruess	0x42(%ecx), %xmm5, %xmm6

	vcmpunord_spd	%xmm0, %xmm1, %xmm2
	vcmpunord_spd	(%eax), %xmm3, %xmm4
	vcmpunord_spd	0x42(%ecx), %xmm5, %xmm6
	vcmpunord_spd	%ymm0, %ymm1, %ymm2
	vcmpunord_spd	(%ebx), %ymm3, %ymm4
	vcmpunord_spd	0x42(%edx), %ymm5, %ymm6

	vcmpunord_sps	%xmm0, %xmm1, %xmm2
	vcmpunord_sps	(%eax), %xmm3, %xmm4
	vcmpunord_sps	0x42(%ecx), %xmm5, %xmm6
	vcmpunord_sps	%ymm0, %ymm1, %ymm2
	vcmpunord_sps	(%ebx), %ymm3, %ymm4
	vcmpunord_sps	0x42(%edx), %ymm5, %ymm6

	vcmpunord_ssd	%xmm0, %xmm1, %xmm2
	vcmpunord_ssd	(%eax), %xmm3, %xmm4
	vcmpunord_ssd	0x42(%ecx), %xmm5, %xmm6

	vcmpunord_sss	%xmm0, %xmm1, %xmm2
	vcmpunord_sss	(%eax), %xmm3, %xmm4
	vcmpunord_sss	0x42(%ecx), %xmm5, %xmm6

	vcmpunordpd	%xmm0, %xmm1, %xmm2
	vcmpunordpd	(%eax), %xmm3, %xmm4
	vcmpunordpd	0x42(%ecx), %xmm5, %xmm6
	vcmpunordpd	%ymm0, %ymm1, %ymm2
	vcmpunordpd	(%ebx), %ymm3, %ymm4
	vcmpunordpd	0x42(%edx), %ymm5, %ymm6

	vcmpunordps	%xmm0, %xmm1, %xmm2
	vcmpunordps	(%eax), %xmm3, %xmm4
	vcmpunordps	0x42(%ecx), %xmm5, %xmm6
	vcmpunordps	%ymm0, %ymm1, %ymm2
	vcmpunordps	(%ebx), %ymm3, %ymm4
	vcmpunordps	0x42(%edx), %ymm5, %ymm6

	vcmpunordsd	%xmm0, %xmm1, %xmm2
	vcmpunordsd	(%eax), %xmm3, %xmm4
	vcmpunordsd	0x42(%ecx), %xmm5, %xmm6

	vcmpunordss	%xmm0, %xmm1, %xmm2
	vcmpunordss	(%eax), %xmm3, %xmm4
	vcmpunordss	0x42(%ecx), %xmm5, %xmm6

	vcomisd	%xmm0, %xmm1
	vcomisd	(%esi), %xmm3
	vcomisd	0x42(%edi), %xmm3

	vcomiss	%xmm0, %xmm1
	vcomiss	(%esi), %xmm3
	vcomiss	0x42(%edi), %xmm3

	vcvtdq2pd	%xmm0, %xmm1
	vcvtdq2pd	(%esi), %xmm3
	vcvtdq2pd	0x42(%edi), %xmm3
	vcvtdq2pd	%xmm7, %ymm6
	vcvtdq2pd	(%ebp), %ymm4
	vcvtdq2pd	0x42(%esp), %ymm4

	vcvtdq2ps	%xmm0, %xmm1
	vcvtdq2ps	(%esi), %xmm3
	vcvtdq2ps	0x42(%edi), %xmm3
	vcvtdq2ps	%ymm7, %ymm6
	vcvtdq2ps	(%ebp), %ymm4
	vcvtdq2ps	0x42(%esp), %ymm4

	vcvtpd2dq	%ymm6, %xmm3

	vcvtpd2dqx	%xmm0, %xmm1
	vcvtpd2dqx	(%esi), %xmm3
	vcvtpd2dqx	0x42(%edi), %xmm3

	vcvtpd2dqy	%ymm7, %xmm6
	vcvtpd2dqy	(%ebp), %xmm4
	vcvtpd2dqy	0x42(%esp), %xmm4

	vcvtpd2ps	%ymm6, %xmm3

	vcvtpd2psx	%xmm0, %xmm1
	vcvtpd2psx	(%esi), %xmm3
	vcvtpd2psx	0x42(%edi), %xmm3

	vcvtpd2psy	%ymm7, %xmm6
	vcvtpd2psy	(%ebp), %xmm4
	vcvtpd2psy	0x42(%esp), %xmm4

	vcvtps2dq	%xmm0, %xmm1
	vcvtps2dq	(%esi), %xmm3
	vcvtps2dq	0x42(%edi), %xmm3
	vcvtps2dq	%ymm7, %ymm6
	vcvtps2dq	(%ebp), %ymm4
	vcvtps2dq	0x42(%esp), %ymm4

	vcvtps2pd	%xmm0, %xmm1
	vcvtps2pd	(%esi), %xmm3
	vcvtps2pd	0x42(%edi), %xmm3
	vcvtps2pd	%xmm7, %ymm6
	vcvtps2pd	(%ebp), %ymm4
	vcvtps2pd	0x42(%esp), %ymm4

	vcvtsd2si	%xmm6, %eax
	vcvtsd2si	(%ebx), %eax
	vcvtsd2si	0x24(%ebx), %eax

	vcvtsd2ss	%xmm0, %xmm1, %xmm2
	vcvtsd2ss	(%eax), %xmm3, %xmm4
	vcvtsd2ss	0x42(%ecx), %xmm5, %xmm6

	vcvtss2sd	%xmm0, %xmm1, %xmm2
	vcvtss2sd	(%eax), %xmm3, %xmm4
	vcvtss2sd	0x42(%ecx), %xmm5, %xmm6

	vcvtss2si	%xmm6, %eax
	vcvtss2si	(%ebx), %eax
	vcvtss2si	0x24(%ebx), %eax

	vcvttpd2dq	%xmm0, %xmm5

	vcvttpd2dqx	%xmm0, %xmm1
	vcvttpd2dqx	(%esi), %xmm3
	vcvttpd2dqx	0x42(%edi), %xmm3

	vcvttpd2dqy	%ymm7, %xmm6
	vcvttpd2dqy	(%ebp), %xmm4
	vcvttpd2dqy	0x42(%esp), %xmm4

	vcvttps2dq	%xmm0, %xmm1
	vcvttps2dq	(%esi), %xmm3
	vcvttps2dq	0x42(%edi), %xmm3
	vcvttps2dq	%ymm7, %ymm6
	vcvttps2dq	(%ebp), %ymm4
	vcvttps2dq	0x42(%esp), %ymm4

	vcvttsd2si	%xmm6, %eax
	vcvttsd2si	(%ebx), %eax
	vcvttsd2si	0x24(%ebx), %eax

	vcvttss2si	%xmm6, %eax
	vcvttss2si	(%ebx), %eax
	vcvttss2si	0x24(%ebx), %eax

	vdivpd	%xmm0, %xmm1, %xmm2
	vdivpd	(%eax), %xmm3, %xmm4
	vdivpd	0x42(%ecx), %xmm5, %xmm6
	vdivpd	%ymm0, %ymm1, %ymm2
	vdivpd	(%ebx), %ymm3, %ymm4
	vdivpd	0x42(%edx), %ymm5, %ymm6

	vdivps	%xmm0, %xmm1, %xmm2
	vdivps	(%eax), %xmm3, %xmm4
	vdivps	0x42(%ecx), %xmm5, %xmm6
	vdivps	%ymm0, %ymm1, %ymm2
	vdivps	(%ebx), %ymm3, %ymm4
	vdivps	0x42(%edx), %ymm5, %ymm6

	vdivsd	%xmm0, %xmm1, %xmm2
	vdivsd	(%eax), %xmm3, %xmm4
	vdivsd	0x42(%ecx), %xmm5, %xmm6

	vdivss	%xmm0, %xmm1, %xmm2
	vdivss	(%eax), %xmm3, %xmm4
	vdivss	0x42(%ecx), %xmm5, %xmm6

	vdppd	$0x48, %xmm3, %xmm5, %xmm7
	vdppd	$0x48, (%ebx), %xmm2, %xmm4
	vdppd	$0x48, 0x8(%ebx), %xmm1, %xmm6

	vdpps	$0x48, %xmm3, %xmm5, %xmm7
	vdpps	$0x48, (%ebx), %xmm2, %xmm4
	vdpps	$0x48, 0x8(%ebx), %xmm1, %xmm6
	vdpps	$0x48, %ymm3, %ymm5, %ymm7
	vdpps	$0x48, (%ebx), %ymm2, %ymm4
	vdpps	$0x48, 0x8(%ebx), %ymm1, %ymm6

	vextractf128	$0x30, %ymm0, %xmm1
	vextractf128	$0x30, %ymm0, (%ecx)
	vextractf128	$0x30, %ymm0, 0x24(%edx)

	vextractps	$0x30, %xmm0, %eax
	vextractps	$0x30, %xmm0, (%ecx)
	vextractps	$0x30, %xmm0, 0x24(%edx)

	vhaddpd	%xmm0, %xmm1, %xmm2
	vhaddpd	(%eax), %xmm3, %xmm4
	vhaddpd	0x42(%ecx), %xmm5, %xmm6
	vhaddpd	%ymm0, %ymm1, %ymm2
	vhaddpd	(%ebx), %ymm3, %ymm4
	vhaddpd	0x42(%edx), %ymm5, %ymm6

	vhaddps	%xmm0, %xmm1, %xmm2
	vhaddps	(%eax), %xmm3, %xmm4
	vhaddps	0x42(%ecx), %xmm5, %xmm6
	vhaddps	%ymm0, %ymm1, %ymm2
	vhaddps	(%ebx), %ymm3, %ymm4
	vhaddps	0x42(%edx), %ymm5, %ymm6

	vhsubpd	%xmm0, %xmm1, %xmm2
	vhsubpd	(%eax), %xmm3, %xmm4
	vhsubpd	0x42(%ecx), %xmm5, %xmm6
	vhsubpd	%ymm0, %ymm1, %ymm2
	vhsubpd	(%ebx), %ymm3, %ymm4
	vhsubpd	0x42(%edx), %ymm5, %ymm6

	vhsubps	%xmm0, %xmm1, %xmm2
	vhsubps	(%eax), %xmm3, %xmm4
	vhsubps	0x42(%ecx), %xmm5, %xmm6
	vhsubps	%ymm0, %ymm1, %ymm2
	vhsubps	(%ebx), %ymm3, %ymm4
	vhsubps	0x42(%edx), %ymm5, %ymm6

	vinsertf128	$0x48, %xmm3, %ymm5, %ymm7
	vinsertf128	$0x48, (%ebx), %ymm2, %ymm4
	vinsertf128	$0x48, 0x8(%ebx), %ymm1, %ymm6

	vinsertps	$0x48, %xmm3, %xmm5, %xmm7
	vinsertps	$0x48, (%ebx), %xmm2, %xmm4
	vinsertps	$0x48, 0x8(%ebx), %xmm1, %xmm6

	vlddqu	(%ebx), %xmm2
	vlddqu	0x8(%ebx), %xmm1
	vlddqu	(%ebx), %ymm2
	vlddqu	0x8(%ebx), %ymm1

	vldmxcsr	(%edx)
	vldmxcsr	0x8(%edx)

	vmaskmovdqu	%xmm0, %xmm5

	vmaskmovpd	(%ebx), %xmm4, %xmm2
	vmaskmovpd	0x8(%ebx), %xmm2, %xmm1

	vmaskmovps	(%ebx), %ymm4, %ymm2
	vmaskmovps	0x8(%ebx), %ymm3, %ymm1

	vmaxpd	%xmm0, %xmm1, %xmm2
	vmaxpd	(%eax), %xmm3, %xmm4
	vmaxpd	0x42(%ecx), %xmm5, %xmm6
	vmaxpd	%ymm0, %ymm1, %ymm2
	vmaxpd	(%ebx), %ymm3, %ymm4
	vmaxpd	0x42(%edx), %ymm5, %ymm6

	vmaxps	%xmm0, %xmm1, %xmm2
	vmaxps	(%eax), %xmm3, %xmm4
	vmaxps	0x42(%ecx), %xmm5, %xmm6
	vmaxps	%ymm0, %ymm1, %ymm2
	vmaxps	(%ebx), %ymm3, %ymm4
	vmaxps	0x42(%edx), %ymm5, %ymm6

	vmaxsd	%xmm0, %xmm1, %xmm2
	vmaxsd	(%eax), %xmm3, %xmm4
	vmaxsd	0x42(%ecx), %xmm5, %xmm6

	vmaxss	%xmm0, %xmm1, %xmm2
	vmaxss	(%eax), %xmm3, %xmm4
	vmaxss	0x42(%ecx), %xmm5, %xmm6

	vminpd	%xmm0, %xmm1, %xmm2
	vminpd	(%eax), %xmm3, %xmm4
	vminpd	0x42(%ecx), %xmm5, %xmm6
	vminpd	%ymm0, %ymm1, %ymm2
	vminpd	(%ebx), %ymm3, %ymm4
	vminpd	0x42(%edx), %ymm5, %ymm6

	vminps	%xmm0, %xmm1, %xmm2
	vminps	(%eax), %xmm3, %xmm4
	vminps	0x42(%ecx), %xmm5, %xmm6
	vminps	%ymm0, %ymm1, %ymm2
	vminps	(%ebx), %ymm3, %ymm4
	vminps	0x42(%edx), %ymm5, %ymm6

	vminsd	%xmm0, %xmm1, %xmm2
	vminsd	(%eax), %xmm3, %xmm4
	vminsd	0x42(%ecx), %xmm5, %xmm6

	vminss	%xmm0, %xmm1, %xmm2
	vminss	(%eax), %xmm3, %xmm4
	vminss	0x42(%ecx), %xmm5, %xmm6

	vmovapd	%xmm0, %xmm1
	vmovapd	(%esi), %xmm3
	vmovapd	0x42(%edi), %xmm3
	vmovapd	%ymm7, %ymm6
	vmovapd	(%ebp), %ymm4
	vmovapd	0x42(%esp), %ymm4
	vmovapd	%xmm1, %xmm0
	vmovapd	%xmm3, (%esi)
	vmovapd	%xmm3, 0x42(%edi)
	vmovapd	%ymm1, %ymm0
	vmovapd	%ymm3, (%esi)
	vmovapd	%ymm3, 0x42(%edi)

	vmovaps	%xmm0, %xmm1
	vmovaps	(%esi), %xmm3
	vmovaps	0x42(%edi), %xmm3
	vmovaps	%ymm7, %ymm6
	vmovaps	(%ebp), %ymm4
	vmovaps	0x42(%esp), %ymm4
	vmovaps	%xmm1, %xmm0
	vmovaps	%xmm3, (%esi)
	vmovaps	%xmm3, 0x42(%edi)
	vmovaps	%ymm1, %ymm0
	vmovaps	%ymm3, (%esi)
	vmovaps	%ymm3, 0x42(%edi)

	vmovd	%eax, %xmm0
	vmovd	(%eax), %xmm1
	vmovd	0x14(%eax), %xmm1

	vmovddup	%xmm0, %xmm1
	vmovddup	(%esi), %xmm3
	vmovddup	0x42(%edi), %xmm3
	vmovddup	%ymm7, %ymm6
	vmovddup	(%ebp), %ymm4
	vmovddup	0x42(%esp), %ymm4

	vmovdqa	%xmm0, %xmm1
	vmovdqa	(%esi), %xmm3
	vmovdqa	0x42(%edi), %xmm3
	vmovdqa	%ymm7, %ymm6
	vmovdqa	(%ebp), %ymm4
	vmovdqa	0x42(%esp), %ymm4
	vmovdqa	%xmm1, %xmm0
	vmovdqa	%xmm3, (%esi)
	vmovdqa	%xmm3, 0x42(%edi)
	vmovdqa	%ymm1, %ymm0
	vmovdqa	%ymm3, (%esi)
	vmovdqa	%ymm3, 0x42(%edi)

	vmovdqu	%xmm0, %xmm1
	vmovdqu	(%esi), %xmm3
	vmovdqu	0x42(%edi), %xmm3
	vmovdqu	%ymm7, %ymm6
	vmovdqu	(%ebp), %ymm4
	vmovdqu	0x42(%esp), %ymm4
	vmovdqu	%xmm1, %xmm0
	vmovdqu	%xmm3, (%esi)
	vmovdqu	%xmm3, 0x42(%edi)
	vmovdqu	%ymm1, %ymm0
	vmovdqu	%ymm3, (%esi)
	vmovdqu	%ymm3, 0x42(%edi)

	vmovhlps	%xmm0, %xmm2, %xmm4

	vmovhpd	(%ebx), %xmm4, %xmm2
	vmovhpd	0x8(%ebx), %xmm3, %xmm1
	vmovhpd	%xmm3, (%esi)
	vmovhpd	%xmm3, 0x42(%edi)

	vmovhps	(%ebx), %xmm4, %xmm2
	vmovhps	0x8(%ebx), %xmm3, %xmm1
	vmovhps	%xmm3, (%esi)
	vmovhps	%xmm3, 0x42(%edi)

	vmovlhps	%xmm1, %xmm3, %xmm5

	vmovlpd	(%ebx), %xmm4, %xmm2
	vmovlpd	0x8(%ebx), %xmm3, %xmm1
	vmovlpd	%xmm3, (%esi)
	vmovlpd	%xmm3, 0x42(%edi)

	vmovlps	(%ebx), %xmm4, %xmm2
	vmovlps	0x8(%ebx), %xmm3, %xmm1
	vmovlps	%xmm3, (%esi)
	vmovlps	%xmm3, 0x42(%edi)

	vmovmskpd	%xmm0, %eax
	vmovmskpd	%ymm1, %ebx

	vmovmskps	%xmm2, %ecx
	vmovmskps	%ymm3, %edx

	vmovntdq	%xmm5, (%edi)
	vmovntdq	%xmm5, 0x24(%edi)
	vmovntdq	%ymm6, (%esi)
	vmovntdq	%ymm6, 0x24(%esi)

	vmovntdqa	(%ebx), %xmm2
	vmovntdqa	0x8(%ebx), %xmm1
	vmovntdqa	(%ebx), %ymm2
	vmovntdqa	0x8(%ebx), %ymm1

	vmovntpd	%xmm3, (%esi)
	vmovntpd	%xmm3, 0x42(%edi)
	vmovntpd	%ymm3, (%esi)
	vmovntpd	%ymm3, 0x42(%edi)

	vmovntps	%xmm3, (%esi)
	vmovntps	%xmm3, 0x42(%edi)
	vmovntps	%ymm3, (%esi)
	vmovntps	%ymm3, 0x42(%edi)

	vmovq	%xmm0, (%eax)
	vmovq	%xmm0, 0x10(%eax)
	vmovq	0x10(%ebx), %xmm1
	vmovq	(%ebx), %xmm1

	vmovsd	%xmm0, %xmm2, %xmm4
	vmovsd	(%eax), %xmm1
	vmovsd	0x32(%eax), %xmm2

	vmovshdup	%xmm0, %xmm2
	vmovshdup	(%eax), %xmm1
	vmovshdup	0x10(%eax), %xmm1
	vmovshdup	%ymm0, %ymm2
	vmovshdup	(%ebx), %ymm1
	vmovshdup	0x10(%ebx), %ymm3

	vmovsldup	%xmm0, %xmm2
	vmovsldup	(%eax), %xmm1
	vmovsldup	0x10(%eax), %xmm1
	vmovsldup	%ymm0, %ymm2
	vmovsldup	(%ebx), %ymm1
	vmovsldup	0x10(%ebx), %ymm3

	vmovss	%xmm0, %xmm2, %xmm4
	vmovss	(%eax), %xmm1
	vmovss	0x32(%eax), %xmm2

	vmovupd	%xmm0, %xmm1
	vmovupd	(%esi), %xmm3
	vmovupd	0x42(%edi), %xmm3
	vmovupd	%ymm7, %ymm6
	vmovupd	(%ebp), %ymm4
	vmovupd	0x42(%esp), %ymm4
	vmovupd	%xmm1, %xmm0
	vmovupd	%xmm3, (%esi)
	vmovupd	%xmm3, 0x42(%edi)
	vmovupd	%ymm1, %ymm0
	vmovupd	%ymm3, (%esi)
	vmovupd	%ymm3, 0x42(%edi)

	vmovups	%xmm0, %xmm1
	vmovups	(%esi), %xmm3
	vmovups	0x42(%edi), %xmm3
	vmovups	%ymm7, %ymm6
	vmovups	(%ebp), %ymm4
	vmovups	0x42(%esp), %ymm4
	vmovups	%xmm1, %xmm0
	vmovups	%xmm3, (%esi)
	vmovups	%xmm3, 0x42(%edi)
	vmovups	%ymm1, %ymm0
	vmovups	%ymm3, (%esi)
	vmovups	%ymm3, 0x42(%edi)

	vmpsadbw	$0x48, %xmm3, %xmm5, %xmm7
	vmpsadbw	$0x48, (%ebx), %xmm2, %xmm4
	vmpsadbw	$0x48, 0x8(%ebx), %xmm1, %xmm6
	vmpsadbw	$0x48, %ymm3, %ymm5, %ymm7
	vmpsadbw	$0x48, (%ebx), %ymm2, %ymm4
	vmpsadbw	$0x48, 0x8(%ebx), %ymm1, %ymm6

	vmulpd	%xmm0, %xmm1, %xmm2
	vmulpd	(%eax), %xmm3, %xmm4
	vmulpd	0x42(%ecx), %xmm5, %xmm6
	vmulpd	%ymm0, %ymm1, %ymm2
	vmulpd	(%ebx), %ymm3, %ymm4
	vmulpd	0x42(%edx), %ymm5, %ymm6

	vmulps	%xmm0, %xmm1, %xmm2
	vmulps	(%eax), %xmm3, %xmm4
	vmulps	0x42(%ecx), %xmm5, %xmm6
	vmulps	%ymm0, %ymm1, %ymm2
	vmulps	(%ebx), %ymm3, %ymm4
	vmulps	0x42(%edx), %ymm5, %ymm6

	vmulsd	%xmm0, %xmm1, %xmm2
	vmulsd	(%eax), %xmm3, %xmm4
	vmulsd	0x42(%ecx), %xmm5, %xmm6

	vmulss	%xmm0, %xmm1, %xmm2
	vmulss	(%eax), %xmm3, %xmm4
	vmulss	0x42(%ecx), %xmm5, %xmm6

	vorpd	%xmm0, %xmm1, %xmm2
	vorpd	(%eax), %xmm3, %xmm4
	vorpd	0x42(%ecx), %xmm5, %xmm6
	vorpd	%ymm0, %ymm1, %ymm2
	vorpd	(%ebx), %ymm3, %ymm4
	vorpd	0x42(%edx), %ymm5, %ymm6

	vorps	%xmm0, %xmm1, %xmm2
	vorps	(%eax), %xmm3, %xmm4
	vorps	0x42(%ecx), %xmm5, %xmm6
	vorps	%ymm0, %ymm1, %ymm2
	vorps	(%ebx), %ymm3, %ymm4
	vorps	0x42(%edx), %ymm5, %ymm6

	vpabsb	%xmm0, %xmm1
	vpabsb	(%esi), %xmm3
	vpabsb	0x42(%edi), %xmm3
	vpabsb	%ymm7, %ymm6
	vpabsb	(%ebp), %ymm4
	vpabsb	0x42(%esp), %ymm4

	vpabsd	%xmm0, %xmm1
	vpabsd	(%esi), %xmm3
	vpabsd	0x42(%edi), %xmm3
	vpabsd	%ymm7, %ymm6
	vpabsd	(%ebp), %ymm4
	vpabsd	0x42(%esp), %ymm4

	vpabsw	%xmm0, %xmm1
	vpabsw	(%esi), %xmm3
	vpabsw	0x42(%edi), %xmm3
	vpabsw	%ymm7, %ymm6
	vpabsw	(%ebp), %ymm4
	vpabsw	0x42(%esp), %ymm4

	vpackssdw	%xmm0, %xmm1, %xmm2
	vpackssdw	(%eax), %xmm3, %xmm4
	vpackssdw	0x42(%ecx), %xmm5, %xmm6
	vpackssdw	%ymm0, %ymm1, %ymm2
	vpackssdw	(%ebx), %ymm3, %ymm4
	vpackssdw	0x42(%edx), %ymm5, %ymm6

	vpacksswb	%xmm0, %xmm1, %xmm2
	vpacksswb	(%eax), %xmm3, %xmm4
	vpacksswb	0x42(%ecx), %xmm5, %xmm6
	vpacksswb	%ymm0, %ymm1, %ymm2
	vpacksswb	(%ebx), %ymm3, %ymm4
	vpacksswb	0x42(%edx), %ymm5, %ymm6

	vpackusdw	%xmm0, %xmm1, %xmm2
	vpackusdw	(%eax), %xmm3, %xmm4
	vpackusdw	0x42(%ecx), %xmm5, %xmm6
	vpackusdw	%ymm0, %ymm1, %ymm2
	vpackusdw	(%ebx), %ymm3, %ymm4
	vpackusdw	0x42(%edx), %ymm5, %ymm6

	vpackuswb	%xmm0, %xmm1, %xmm2
	vpackuswb	(%eax), %xmm3, %xmm4
	vpackuswb	0x42(%ecx), %xmm5, %xmm6
	vpackuswb	%ymm0, %ymm1, %ymm2
	vpackuswb	(%ebx), %ymm3, %ymm4
	vpackuswb	0x42(%edx), %ymm5, %ymm6

	vpaddb	%xmm0, %xmm1, %xmm2
	vpaddb	(%eax), %xmm3, %xmm4
	vpaddb	0x42(%ecx), %xmm5, %xmm6
	vpaddb	%ymm0, %ymm1, %ymm2
	vpaddb	(%ebx), %ymm3, %ymm4
	vpaddb	0x42(%edx), %ymm5, %ymm6

	vpaddd	%xmm0, %xmm1, %xmm2
	vpaddd	(%eax), %xmm3, %xmm4
	vpaddd	0x42(%ecx), %xmm5, %xmm6
	vpaddd	%ymm0, %ymm1, %ymm2
	vpaddd	(%ebx), %ymm3, %ymm4
	vpaddd	0x42(%edx), %ymm5, %ymm6

	vpaddq	%xmm0, %xmm1, %xmm2
	vpaddq	(%eax), %xmm3, %xmm4
	vpaddq	0x42(%ecx), %xmm5, %xmm6
	vpaddq	%ymm0, %ymm1, %ymm2
	vpaddq	(%ebx), %ymm3, %ymm4
	vpaddq	0x42(%edx), %ymm5, %ymm6

	vpaddsb	%xmm0, %xmm1, %xmm2
	vpaddsb	(%eax), %xmm3, %xmm4
	vpaddsb	0x42(%ecx), %xmm5, %xmm6
	vpaddsb	%ymm0, %ymm1, %ymm2
	vpaddsb	(%ebx), %ymm3, %ymm4
	vpaddsb	0x42(%edx), %ymm5, %ymm6

	vpaddsw	%xmm0, %xmm1, %xmm2
	vpaddsw	(%eax), %xmm3, %xmm4
	vpaddsw	0x42(%ecx), %xmm5, %xmm6
	vpaddsw	%ymm0, %ymm1, %ymm2
	vpaddsw	(%ebx), %ymm3, %ymm4
	vpaddsw	0x42(%edx), %ymm5, %ymm6

	vpaddusb	%xmm0, %xmm1, %xmm2
	vpaddusb	(%eax), %xmm3, %xmm4
	vpaddusb	0x42(%ecx), %xmm5, %xmm6
	vpaddusb	%ymm0, %ymm1, %ymm2
	vpaddusb	(%ebx), %ymm3, %ymm4
	vpaddusb	0x42(%edx), %ymm5, %ymm6

	vpaddusw	%xmm0, %xmm1, %xmm2
	vpaddusw	(%eax), %xmm3, %xmm4
	vpaddusw	0x42(%ecx), %xmm5, %xmm6
	vpaddusw	%ymm0, %ymm1, %ymm2
	vpaddusw	(%ebx), %ymm3, %ymm4
	vpaddusw	0x42(%edx), %ymm5, %ymm6

	vpaddw	%xmm0, %xmm1, %xmm2
	vpaddw	(%eax), %xmm3, %xmm4
	vpaddw	0x42(%ecx), %xmm5, %xmm6
	vpaddw	%ymm0, %ymm1, %ymm2
	vpaddw	(%ebx), %ymm3, %ymm4
	vpaddw	0x42(%edx), %ymm5, %ymm6

	vpalignr	$0x48, %xmm3, %xmm5, %xmm7
	vpalignr	$0x48, (%ebx), %xmm2, %xmm4
	vpalignr	$0x48, 0x8(%ebx), %xmm1, %xmm6
	vpalignr	$0x48, %ymm3, %ymm5, %ymm7
	vpalignr	$0x48, (%ebx), %ymm2, %ymm4
	vpalignr	$0x48, 0x8(%ebx), %ymm1, %ymm6

	vpand	%xmm0, %xmm1, %xmm2
	vpand	(%eax), %xmm3, %xmm4
	vpand	0x42(%ecx), %xmm5, %xmm6
	vpand	%ymm0, %ymm1, %ymm2
	vpand	(%ebx), %ymm3, %ymm4
	vpand	0x42(%edx), %ymm5, %ymm6

	vpandn	%xmm0, %xmm1, %xmm2
	vpandn	(%eax), %xmm3, %xmm4
	vpandn	0x42(%ecx), %xmm5, %xmm6
	vpandn	%ymm0, %ymm1, %ymm2
	vpandn	(%ebx), %ymm3, %ymm4
	vpandn	0x42(%edx), %ymm5, %ymm6

	vpavgb	%xmm0, %xmm1, %xmm2
	vpavgb	(%eax), %xmm3, %xmm4
	vpavgb	0x42(%ecx), %xmm5, %xmm6
	vpavgb	%ymm0, %ymm1, %ymm2
	vpavgb	(%ebx), %ymm3, %ymm4
	vpavgb	0x42(%edx), %ymm5, %ymm6

	vpavgw	%xmm0, %xmm1, %xmm2
	vpavgw	(%eax), %xmm3, %xmm4
	vpavgw	0x42(%ecx), %xmm5, %xmm6
	vpavgw	%ymm0, %ymm1, %ymm2
	vpavgw	(%ebx), %ymm3, %ymm4
	vpavgw	0x42(%edx), %ymm5, %ymm6

	vpblendvb	%xmm0, %xmm1, %xmm2, %xmm3
	vpblendvb	%xmm0, (%eax), %xmm2, %xmm3
	vpblendvb	%xmm0, 0x10(%ebx), %xmm2, %xmm3
	vpblendvb	%ymm0, %ymm1, %ymm2, %ymm3
	vpblendvb	%ymm0, (%eax), %ymm2, %ymm3
	vpblendvb	%ymm0, 0x10(%ebx), %ymm2, %ymm3

	vpblendw	$0x48, %xmm3, %xmm5, %xmm7
	vpblendw	$0x48, (%ebx), %xmm2, %xmm4
	vpblendw	$0x48, 0x8(%ebx), %xmm1, %xmm6
	vpblendw	$0x48, %ymm3, %ymm5, %ymm7
	vpblendw	$0x48, (%ebx), %ymm2, %ymm4
	vpblendw	$0x48, 0x8(%ebx), %ymm1, %ymm6

	vpclmulqdq	$0x48, %xmm3, %xmm5, %xmm7
	vpclmulqdq	$0x48, (%ebx), %xmm2, %xmm4
	vpclmulqdq	$0x48, 0x8(%ebx), %xmm1, %xmm6

	vpcmpeqb	%xmm0, %xmm1, %xmm2
	vpcmpeqb	(%eax), %xmm3, %xmm4
	vpcmpeqb	0x42(%ecx), %xmm5, %xmm6
	vpcmpeqb	%ymm0, %ymm1, %ymm2
	vpcmpeqb	(%ebx), %ymm3, %ymm4
	vpcmpeqb	0x42(%edx), %ymm5, %ymm6

	vpcmpeqd	%xmm0, %xmm1, %xmm2
	vpcmpeqd	(%eax), %xmm3, %xmm4
	vpcmpeqd	0x42(%ecx), %xmm5, %xmm6
	vpcmpeqd	%ymm0, %ymm1, %ymm2
	vpcmpeqd	(%ebx), %ymm3, %ymm4
	vpcmpeqd	0x42(%edx), %ymm5, %ymm6

	vpcmpeqq	%xmm0, %xmm1, %xmm2
	vpcmpeqq	(%eax), %xmm3, %xmm4
	vpcmpeqq	0x42(%ecx), %xmm5, %xmm6
	vpcmpeqq	%ymm0, %ymm1, %ymm2
	vpcmpeqq	(%ebx), %ymm3, %ymm4
	vpcmpeqq	0x42(%edx), %ymm5, %ymm6

	vpcmpeqw	%xmm0, %xmm1, %xmm2
	vpcmpeqw	(%eax), %xmm3, %xmm4
	vpcmpeqw	0x42(%ecx), %xmm5, %xmm6
	vpcmpeqw	%ymm0, %ymm1, %ymm2
	vpcmpeqw	(%ebx), %ymm3, %ymm4
	vpcmpeqw	0x42(%edx), %ymm5, %ymm6

	vpcmpestri	$0x42, %xmm0, %xmm1
	vpcmpestri	$0x23, 	(%esi), %xmm3
	vpcmpestri	$0x42, 0x42(%edi), %xmm3

	vpcmpestrm	$0x42, %xmm0, %xmm1
	vpcmpestrm	$0x23, 	(%esi), %xmm3
	vpcmpestrm	$0x42, 0x42(%edi), %xmm3

	vpcmpgtb	%xmm0, %xmm1, %xmm2
	vpcmpgtb	(%eax), %xmm3, %xmm4
	vpcmpgtb	0x42(%ecx), %xmm5, %xmm6
	vpcmpgtb	%ymm0, %ymm1, %ymm2
	vpcmpgtb	(%ebx), %ymm3, %ymm4
	vpcmpgtb	0x42(%edx), %ymm5, %ymm6

	vpcmpgtd	%xmm0, %xmm1, %xmm2
	vpcmpgtd	(%eax), %xmm3, %xmm4
	vpcmpgtd	0x42(%ecx), %xmm5, %xmm6
	vpcmpgtd	%ymm0, %ymm1, %ymm2
	vpcmpgtd	(%ebx), %ymm3, %ymm4
	vpcmpgtd	0x42(%edx), %ymm5, %ymm6

	vpcmpgtq	%xmm0, %xmm1, %xmm2
	vpcmpgtq	(%eax), %xmm3, %xmm4
	vpcmpgtq	0x42(%ecx), %xmm5, %xmm6
	vpcmpgtq	%ymm0, %ymm1, %ymm2
	vpcmpgtq	(%ebx), %ymm3, %ymm4
	vpcmpgtq	0x42(%edx), %ymm5, %ymm6

	vpcmpgtw	%xmm0, %xmm1, %xmm2
	vpcmpgtw	(%eax), %xmm3, %xmm4
	vpcmpgtw	0x42(%ecx), %xmm5, %xmm6
	vpcmpgtw	%ymm0, %ymm1, %ymm2
	vpcmpgtw	(%ebx), %ymm3, %ymm4
	vpcmpgtw	0x42(%edx), %ymm5, %ymm6

	vpcmpistri	$0x42, %xmm0, %xmm1
	vpcmpistri	$0x23, 	(%esi), %xmm3
	vpcmpistri	$0x42, 0x42(%edi), %xmm3

	vpcmpistrm	$0x42, %xmm0, %xmm1
	vpcmpistrm	$0x23, 	(%esi), %xmm3
	vpcmpistrm	$0x42, 0x42(%edi), %xmm3

	vperm2f128	$0x48, %ymm3, %ymm5, %ymm7
	vperm2f128	$0x48, (%ebx), %ymm2, %ymm4
	vperm2f128	$0x48, 0x8(%ebx), %ymm1, %ymm6

	vpermilpd	%xmm0, %xmm1, %xmm2
	vpermilpd	(%eax), %xmm3, %xmm4
	vpermilpd	0x42(%ecx), %xmm5, %xmm6
	vpermilpd	%ymm0, %ymm1, %ymm2
	vpermilpd	(%ebx), %ymm3, %ymm4
	vpermilpd	0x42(%edx), %ymm5, %ymm6
	vpermilpd	$0x42, %ymm0, %ymm1
	vpermilpd	$0x23, 	(%esi), %ymm3
	vpermilpd	$0x42, 0x42(%edi), %ymm3

	vpermilps	%xmm0, %xmm1, %xmm2
	vpermilps	(%eax), %xmm3, %xmm4
	vpermilps	0x42(%ecx), %xmm5, %xmm6
	vpermilps	%ymm0, %ymm1, %ymm2
	vpermilps	(%ebx), %ymm3, %ymm4
	vpermilps	0x42(%edx), %ymm5, %ymm6
	vpermilps	$0x42, %ymm0, %ymm1
	vpermilps	$0x23, 	(%esi), %ymm3
	vpermilps	$0x42, 0x42(%edi), %ymm3

	vpextrb	$0x23, %xmm0, %eax
	vpextrb	$0x23, %xmm1, (%ebx)
	vpextrb	$0x23, %xmm2, 0x16(%ecx)

	vpextrd	$0x23, %xmm0, %eax
	vpextrd	$0x23, %xmm1, (%ebx)
	vpextrd	$0x23, %xmm2, 0x16(%ecx)

	/*
	 * gas will assemble the following two instructions with an EVEX
	 * prefix. Force the VEX encoding with the correct W bit for the 3-byte
	 * VEX prefix.
	 * vpextrq	$0x23, %xmm1, (%ebx)
	 * vpextrq	$0x23, %xmm2, 0x16(%ecx)
	 */
	.byte	0xc4, 0xe3, 0xf9, 0x16, 0x0b, 0x23
	.byte	0xc4, 0xe3, 0xf9, 0x16, 0x51, 0x16, 0x23

	vpextrw	$0x23, %xmm0, %eax
	vpextrw	$0x23, %xmm1, (%ebx)
	vpextrw	$0x23, %xmm2, 0x16(%ecx)

	vphaddd	%xmm0, %xmm1, %xmm2
	vphaddd	(%eax), %xmm3, %xmm4
	vphaddd	0x42(%ecx), %xmm5, %xmm6
	vphaddd	%ymm0, %ymm1, %ymm2
	vphaddd	(%ebx), %ymm3, %ymm4
	vphaddd	0x42(%edx), %ymm5, %ymm6

	vphaddsw	%xmm0, %xmm1, %xmm2
	vphaddsw	(%eax), %xmm3, %xmm4
	vphaddsw	0x42(%ecx), %xmm5, %xmm6
	vphaddsw	%ymm0, %ymm1, %ymm2
	vphaddsw	(%ebx), %ymm3, %ymm4
	vphaddsw	0x42(%edx), %ymm5, %ymm6

	vphaddw	%xmm0, %xmm1, %xmm2
	vphaddw	(%eax), %xmm3, %xmm4
	vphaddw	0x42(%ecx), %xmm5, %xmm6
	vphaddw	%ymm0, %ymm1, %ymm2
	vphaddw	(%ebx), %ymm3, %ymm4
	vphaddw	0x42(%edx), %ymm5, %ymm6

	vphminposuw	%xmm0, %xmm1
	vphminposuw	(%esi), %xmm3
	vphminposuw	0x42(%edi), %xmm3

	vphsubd	%xmm0, %xmm1, %xmm2
	vphsubd	(%eax), %xmm3, %xmm4
	vphsubd	0x42(%ecx), %xmm5, %xmm6
	vphsubd	%ymm0, %ymm1, %ymm2
	vphsubd	(%ebx), %ymm3, %ymm4
	vphsubd	0x42(%edx), %ymm5, %ymm6

	vphsubsw	%xmm0, %xmm1, %xmm2
	vphsubsw	(%eax), %xmm3, %xmm4
	vphsubsw	0x42(%ecx), %xmm5, %xmm6
	vphsubsw	%ymm0, %ymm1, %ymm2
	vphsubsw	(%ebx), %ymm3, %ymm4
	vphsubsw	0x42(%edx), %ymm5, %ymm6

	vphsubw	%xmm0, %xmm1, %xmm2
	vphsubw	(%eax), %xmm3, %xmm4
	vphsubw	0x42(%ecx), %xmm5, %xmm6
	vphsubw	%ymm0, %ymm1, %ymm2
	vphsubw	(%ebx), %ymm3, %ymm4
	vphsubw	0x42(%edx), %ymm5, %ymm6

	vpinsrb	$0x20, %eax, %xmm0, %xmm1
	vpinsrb	$0x20, (%ebx), %xmm2, %xmm3
	vpinsrb	$0x20, 0x10(%ebx), %xmm2, %xmm3

	vpinsrd	$0x20, %eax, %xmm0, %xmm1
	vpinsrd	$0x20, (%ebx), %xmm2, %xmm3
	vpinsrd	$0x20, 0x10(%ebx), %xmm2, %xmm3

	/*
	 * gas will assemble the following two instructions with an EVEX
	 * prefix. Force the VEX encoding with the correct W bit for the 3-byte
	 * VEX prefix.
	 * vpinsrq	$0x20, (%ebx), %xmm2, %xmm3
	 * vpinsrq	$0x20, 0x10(%ebx), %xmm2, %xmm3
	 */
	.byte	0xc4, 0xe3, 0xc9, 0x22, 0x1b, 0x20
	.byte	0xc4, 0xe3, 0xc9, 0x22, 0x5b, 0x10, 0x20

	vpinsrw	$0x20, %eax, %xmm0, %xmm1
	vpinsrw	$0x20, (%ebx), %xmm2, %xmm3
	vpinsrw	$0x20, 0x10(%ebx), %xmm2, %xmm3

	vpmaddubsw	%xmm0, %xmm1, %xmm2
	vpmaddubsw	(%eax), %xmm3, %xmm4
	vpmaddubsw	0x42(%ecx), %xmm5, %xmm6
	vpmaddubsw	%ymm0, %ymm1, %ymm2
	vpmaddubsw	(%ebx), %ymm3, %ymm4
	vpmaddubsw	0x42(%edx), %ymm5, %ymm6

	vpmaddwd	%xmm0, %xmm1, %xmm2
	vpmaddwd	(%eax), %xmm3, %xmm4
	vpmaddwd	0x42(%ecx), %xmm5, %xmm6
	vpmaddwd	%ymm0, %ymm1, %ymm2
	vpmaddwd	(%ebx), %ymm3, %ymm4
	vpmaddwd	0x42(%edx), %ymm5, %ymm6

	vpmaxsb	%xmm0, %xmm1, %xmm2
	vpmaxsb	(%eax), %xmm3, %xmm4
	vpmaxsb	0x42(%ecx), %xmm5, %xmm6
	vpmaxsb	%ymm0, %ymm1, %ymm2
	vpmaxsb	(%ebx), %ymm3, %ymm4
	vpmaxsb	0x42(%edx), %ymm5, %ymm6

	vpmaxsd	%xmm0, %xmm1, %xmm2
	vpmaxsd	(%eax), %xmm3, %xmm4
	vpmaxsd	0x42(%ecx), %xmm5, %xmm6
	vpmaxsd	%ymm0, %ymm1, %ymm2
	vpmaxsd	(%ebx), %ymm3, %ymm4
	vpmaxsd	0x42(%edx), %ymm5, %ymm6

	vpmaxsw	%xmm0, %xmm1, %xmm2
	vpmaxsw	(%eax), %xmm3, %xmm4
	vpmaxsw	0x42(%ecx), %xmm5, %xmm6
	vpmaxsw	%ymm0, %ymm1, %ymm2
	vpmaxsw	(%ebx), %ymm3, %ymm4
	vpmaxsw	0x42(%edx), %ymm5, %ymm6

	vpmaxub	%xmm0, %xmm1, %xmm2
	vpmaxub	(%eax), %xmm3, %xmm4
	vpmaxub	0x42(%ecx), %xmm5, %xmm6
	vpmaxub	%ymm0, %ymm1, %ymm2
	vpmaxub	(%ebx), %ymm3, %ymm4
	vpmaxub	0x42(%edx), %ymm5, %ymm6

	vpmaxud	%xmm0, %xmm1, %xmm2
	vpmaxud	(%eax), %xmm3, %xmm4
	vpmaxud	0x42(%ecx), %xmm5, %xmm6
	vpmaxud	%ymm0, %ymm1, %ymm2
	vpmaxud	(%ebx), %ymm3, %ymm4
	vpmaxud	0x42(%edx), %ymm5, %ymm6

	vpmaxuw	%xmm0, %xmm1, %xmm2
	vpmaxuw	(%eax), %xmm3, %xmm4
	vpmaxuw	0x42(%ecx), %xmm5, %xmm6
	vpmaxuw	%ymm0, %ymm1, %ymm2
	vpmaxuw	(%ebx), %ymm3, %ymm4
	vpmaxuw	0x42(%edx), %ymm5, %ymm6

	vpminsb	%xmm0, %xmm1, %xmm2
	vpminsb	(%eax), %xmm3, %xmm4
	vpminsb	0x42(%ecx), %xmm5, %xmm6
	vpminsb	%ymm0, %ymm1, %ymm2
	vpminsb	(%ebx), %ymm3, %ymm4
	vpminsb	0x42(%edx), %ymm5, %ymm6

	vpminsd	%xmm0, %xmm1, %xmm2
	vpminsd	(%eax), %xmm3, %xmm4
	vpminsd	0x42(%ecx), %xmm5, %xmm6
	vpminsd	%ymm0, %ymm1, %ymm2
	vpminsd	(%ebx), %ymm3, %ymm4
	vpminsd	0x42(%edx), %ymm5, %ymm6

	vpminsw	%xmm0, %xmm1, %xmm2
	vpminsw	(%eax), %xmm3, %xmm4
	vpminsw	0x42(%ecx), %xmm5, %xmm6
	vpminsw	%ymm0, %ymm1, %ymm2
	vpminsw	(%ebx), %ymm3, %ymm4
	vpminsw	0x42(%edx), %ymm5, %ymm6

	vpminub	%xmm0, %xmm1, %xmm2
	vpminub	(%eax), %xmm3, %xmm4
	vpminub	0x42(%ecx), %xmm5, %xmm6
	vpminub	%ymm0, %ymm1, %ymm2
	vpminub	(%ebx), %ymm3, %ymm4
	vpminub	0x42(%edx), %ymm5, %ymm6

	vpminud	%xmm0, %xmm1, %xmm2
	vpminud	(%eax), %xmm3, %xmm4
	vpminud	0x42(%ecx), %xmm5, %xmm6
	vpminud	%ymm0, %ymm1, %ymm2
	vpminud	(%ebx), %ymm3, %ymm4
	vpminud	0x42(%edx), %ymm5, %ymm6

	vpminuw	%xmm0, %xmm1, %xmm2
	vpminuw	(%eax), %xmm3, %xmm4
	vpminuw	0x42(%ecx), %xmm5, %xmm6
	vpminuw	%ymm0, %ymm1, %ymm2
	vpminuw	(%ebx), %ymm3, %ymm4
	vpminuw	0x42(%edx), %ymm5, %ymm6

	vpmovmskb	%xmm0, %eax
	vpmovmskb	%ymm1, %ebx

	vpmovsxbd	%xmm0, %xmm1
	vpmovsxbd	(%esi), %xmm3
	vpmovsxbd	0x42(%edi), %xmm3
	vpmovsxbd	%xmm7, %ymm6
	vpmovsxbd	(%ebp), %ymm4
	vpmovsxbd	0x42(%esp), %ymm4

	vpmovsxbq	%xmm0, %xmm1
	vpmovsxbq	(%esi), %xmm3
	vpmovsxbq	0x42(%edi), %xmm3
	vpmovsxbq	%xmm7, %ymm6
	vpmovsxbq	(%ebp), %ymm4
	vpmovsxbq	0x42(%esp), %ymm4

	vpmovsxbw	%xmm0, %xmm1
	vpmovsxbw	(%esi), %xmm3
	vpmovsxbw	0x42(%edi), %xmm3
	vpmovsxbw	%xmm7, %ymm6
	vpmovsxbw	(%ebp), %ymm4
	vpmovsxbw	0x42(%esp), %ymm4

	vpmovsxdq	%xmm0, %xmm1
	vpmovsxdq	(%esi), %xmm3
	vpmovsxdq	0x42(%edi), %xmm3
	vpmovsxdq	%xmm7, %ymm6
	vpmovsxdq	(%ebp), %ymm4
	vpmovsxdq	0x42(%esp), %ymm4

	vpmovsxwd	%xmm0, %xmm1
	vpmovsxwd	(%esi), %xmm3
	vpmovsxwd	0x42(%edi), %xmm3
	vpmovsxwd	%xmm7, %ymm6
	vpmovsxwd	(%ebp), %ymm4
	vpmovsxwd	0x42(%esp), %ymm4

	vpmovsxwq	%xmm0, %xmm1
	vpmovsxwq	(%esi), %xmm3
	vpmovsxwq	0x42(%edi), %xmm3
	vpmovsxwq	%xmm7, %ymm6
	vpmovsxwq	(%ebp), %ymm4
	vpmovsxwq	0x42(%esp), %ymm4

	vpmovzxbd	%xmm0, %xmm1
	vpmovzxbd	(%esi), %xmm3
	vpmovzxbd	0x42(%edi), %xmm3
	vpmovzxbd	%xmm7, %ymm6
	vpmovzxbd	(%ebp), %ymm4
	vpmovzxbd	0x42(%esp), %ymm4

	vpmovzxbq	%xmm0, %xmm1
	vpmovzxbq	(%esi), %xmm3
	vpmovzxbq	0x42(%edi), %xmm3
	vpmovzxbq	%xmm7, %ymm6
	vpmovzxbq	(%ebp), %ymm4
	vpmovzxbq	0x42(%esp), %ymm4

	vpmovzxbw	%xmm0, %xmm1
	vpmovzxbw	(%esi), %xmm3
	vpmovzxbw	0x42(%edi), %xmm3
	vpmovzxbw	%xmm7, %ymm6
	vpmovzxbw	(%ebp), %ymm4
	vpmovzxbw	0x42(%esp), %ymm4

	vpmovzxdq	%xmm0, %xmm1
	vpmovzxdq	(%esi), %xmm3
	vpmovzxdq	0x42(%edi), %xmm3
	vpmovzxdq	%xmm7, %ymm6
	vpmovzxdq	(%ebp), %ymm4
	vpmovzxdq	0x42(%esp), %ymm4

	vpmovzxwd	%xmm0, %xmm1
	vpmovzxwd	(%esi), %xmm3
	vpmovzxwd	0x42(%edi), %xmm3
	vpmovzxwd	%xmm7, %ymm6
	vpmovzxwd	(%ebp), %ymm4
	vpmovzxwd	0x42(%esp), %ymm4

	vpmovzxwq	%xmm0, %xmm1
	vpmovzxwq	(%esi), %xmm3
	vpmovzxwq	0x42(%edi), %xmm3
	vpmovzxwq	%xmm7, %ymm6
	vpmovzxwq	(%ebp), %ymm4
	vpmovzxwq	0x42(%esp), %ymm4

	vpmuldq	%xmm0, %xmm1, %xmm2
	vpmuldq	(%eax), %xmm3, %xmm4
	vpmuldq	0x42(%ecx), %xmm5, %xmm6
	vpmuldq	%ymm0, %ymm1, %ymm2
	vpmuldq	(%ebx), %ymm3, %ymm4
	vpmuldq	0x42(%edx), %ymm5, %ymm6

	vpmulhrsw	%xmm0, %xmm1, %xmm2
	vpmulhrsw	(%eax), %xmm3, %xmm4
	vpmulhrsw	0x42(%ecx), %xmm5, %xmm6
	vpmulhrsw	%ymm0, %ymm1, %ymm2
	vpmulhrsw	(%ebx), %ymm3, %ymm4
	vpmulhrsw	0x42(%edx), %ymm5, %ymm6

	vpmulhuw	%xmm0, %xmm1, %xmm2
	vpmulhuw	(%eax), %xmm3, %xmm4
	vpmulhuw	0x42(%ecx), %xmm5, %xmm6
	vpmulhuw	%ymm0, %ymm1, %ymm2
	vpmulhuw	(%ebx), %ymm3, %ymm4
	vpmulhuw	0x42(%edx), %ymm5, %ymm6

	vpmulhw	%xmm0, %xmm1, %xmm2
	vpmulhw	(%eax), %xmm3, %xmm4
	vpmulhw	0x42(%ecx), %xmm5, %xmm6
	vpmulhw	%ymm0, %ymm1, %ymm2
	vpmulhw	(%ebx), %ymm3, %ymm4
	vpmulhw	0x42(%edx), %ymm5, %ymm6

	vpmulld	%xmm0, %xmm1, %xmm2
	vpmulld	(%eax), %xmm3, %xmm4
	vpmulld	0x42(%ecx), %xmm5, %xmm6
	vpmulld	%ymm0, %ymm1, %ymm2
	vpmulld	(%ebx), %ymm3, %ymm4
	vpmulld	0x42(%edx), %ymm5, %ymm6

	vpmullw	%xmm0, %xmm1, %xmm2
	vpmullw	(%eax), %xmm3, %xmm4
	vpmullw	0x42(%ecx), %xmm5, %xmm6
	vpmullw	%ymm0, %ymm1, %ymm2
	vpmullw	(%ebx), %ymm3, %ymm4
	vpmullw	0x42(%edx), %ymm5, %ymm6

	vpmuludq	%xmm0, %xmm1, %xmm2
	vpmuludq	(%eax), %xmm3, %xmm4
	vpmuludq	0x42(%ecx), %xmm5, %xmm6
	vpmuludq	%ymm0, %ymm1, %ymm2
	vpmuludq	(%ebx), %ymm3, %ymm4
	vpmuludq	0x42(%edx), %ymm5, %ymm6

	vpor	%xmm0, %xmm1, %xmm2
	vpor	(%eax), %xmm3, %xmm4
	vpor	0x42(%ecx), %xmm5, %xmm6
	vpor	%ymm0, %ymm1, %ymm2
	vpor	(%ebx), %ymm3, %ymm4
	vpor	0x42(%edx), %ymm5, %ymm6

	vpsadbw	%xmm0, %xmm1, %xmm2
	vpsadbw	(%eax), %xmm3, %xmm4
	vpsadbw	0x42(%ecx), %xmm5, %xmm6
	vpsadbw	%ymm0, %ymm1, %ymm2
	vpsadbw	(%ebx), %ymm3, %ymm4
	vpsadbw	0x42(%edx), %ymm5, %ymm6

	vpshufb	%xmm0, %xmm1, %xmm2
	vpshufb	(%eax), %xmm3, %xmm4
	vpshufb	0x42(%ecx), %xmm5, %xmm6
	vpshufb	%ymm0, %ymm1, %ymm2
	vpshufb	(%ebx), %ymm3, %ymm4
	vpshufb	0x42(%edx), %ymm5, %ymm6

	vpshufd	$0x42, %xmm0, %xmm1
	vpshufd	$0x23, 	(%esi), %xmm3
	vpshufd	$0x42, 0x42(%edi), %xmm3
	vpshufd	$0x42, %ymm0, %ymm1
	vpshufd	$0x23, 	(%esi), %ymm3
	vpshufd	$0x42, 0x42(%edi), %ymm3

	vpshufhw	$0x42, %xmm0, %xmm1
	vpshufhw	$0x23, 	(%esi), %xmm3
	vpshufhw	$0x42, 0x42(%edi), %xmm3
	vpshufhw	$0x42, %ymm0, %ymm1
	vpshufhw	$0x23, 	(%esi), %ymm3
	vpshufhw	$0x42, 0x42(%edi), %ymm3

	vpshuflw	$0x42, %xmm0, %xmm1
	vpshuflw	$0x23, 	(%esi), %xmm3
	vpshuflw	$0x42, 0x42(%edi), %xmm3
	vpshuflw	$0x42, %ymm0, %ymm1
	vpshuflw	$0x23, 	(%esi), %ymm3
	vpshuflw	$0x42, 0x42(%edi), %ymm3

	vpsignb	%xmm0, %xmm1, %xmm2
	vpsignb	(%eax), %xmm3, %xmm4
	vpsignb	0x42(%ecx), %xmm5, %xmm6
	vpsignb	%ymm0, %ymm1, %ymm2
	vpsignb	(%ebx), %ymm3, %ymm4
	vpsignb	0x42(%edx), %ymm5, %ymm6

	vpsignd	%xmm0, %xmm1, %xmm2
	vpsignd	(%eax), %xmm3, %xmm4
	vpsignd	0x42(%ecx), %xmm5, %xmm6
	vpsignd	%ymm0, %ymm1, %ymm2
	vpsignd	(%ebx), %ymm3, %ymm4
	vpsignd	0x42(%edx), %ymm5, %ymm6

	vpsignw	%xmm0, %xmm1, %xmm2
	vpsignw	(%eax), %xmm3, %xmm4
	vpsignw	0x42(%ecx), %xmm5, %xmm6
	vpsignw	%ymm0, %ymm1, %ymm2
	vpsignw	(%ebx), %ymm3, %ymm4
	vpsignw	0x42(%edx), %ymm5, %ymm6

	vpslld	%xmm0, %xmm1, %xmm2
	vpslld	(%eax), %xmm3, %xmm4
	vpslld	0x10(%ebx), %xmm4, %xmm5
	vpslld	$0x4, %xmm6, %xmm7
	vpslld	%xmm0, %ymm1, %ymm2
	vpslld	(%eax), %ymm3, %ymm4
	vpslld	0x10(%ebx), %ymm4, %ymm5
	vpslld	$0x4, %ymm6, %ymm7

	vpslldq	$0x7, %xmm0, %xmm1
	vpslldq	$0x7, %ymm0, %ymm1

	vpsllq	%xmm0, %xmm1, %xmm2
	vpsllq	(%eax), %xmm3, %xmm4
	vpsllq	0x10(%ebx), %xmm4, %xmm5
	vpsllq	$0x4, %xmm6, %xmm7
	vpsllq	%xmm0, %ymm1, %ymm2
	vpsllq	(%eax), %ymm3, %ymm4
	vpsllq	0x10(%ebx), %ymm4, %ymm5
	vpsllq	$0x4, %ymm6, %ymm7

	vpsllw	%xmm0, %xmm1, %xmm2
	vpsllw	(%eax), %xmm3, %xmm4
	vpsllw	0x10(%ebx), %xmm4, %xmm5
	vpsllw	$0x4, %xmm6, %xmm7
	vpsllw	%xmm0, %ymm1, %ymm2
	vpsllw	(%eax), %ymm3, %ymm4
	vpsllw	0x10(%ebx), %ymm4, %ymm5
	vpsllw	$0x4, %ymm6, %ymm7

	vpsrad	%xmm0, %xmm1, %xmm2
	vpsrad	(%eax), %xmm3, %xmm4
	vpsrad	0x10(%ebx), %xmm4, %xmm5
	vpsrad	$0x4, %xmm6, %xmm7
	vpsrad	%xmm0, %ymm1, %ymm2
	vpsrad	(%eax), %ymm3, %ymm4
	vpsrad	0x10(%ebx), %ymm4, %ymm5
	vpsrad	$0x4, %ymm6, %ymm7

	vpsraw	%xmm0, %xmm1, %xmm2
	vpsraw	(%eax), %xmm3, %xmm4
	vpsraw	0x10(%ebx), %xmm4, %xmm5
	vpsraw	$0x4, %xmm6, %xmm7
	vpsraw	%xmm0, %ymm1, %ymm2
	vpsraw	(%eax), %ymm3, %ymm4
	vpsraw	0x10(%ebx), %ymm4, %ymm5
	vpsraw	$0x4, %ymm6, %ymm7

	vpsrld	%xmm0, %xmm1, %xmm2
	vpsrld	(%eax), %xmm3, %xmm4
	vpsrld	0x10(%ebx), %xmm4, %xmm5
	vpsrld	$0x4, %xmm6, %xmm7
	vpsrld	%xmm0, %ymm1, %ymm2
	vpsrld	(%eax), %ymm3, %ymm4
	vpsrld	0x10(%ebx), %ymm4, %ymm5
	vpsrld	$0x4, %ymm6, %ymm7

	vpsrldq	$0x7, %xmm0, %xmm1
	vpsrldq	$0x7, %ymm0, %ymm1

	vpsrlq	%xmm0, %xmm1, %xmm2
	vpsrlq	(%eax), %xmm3, %xmm4
	vpsrlq	0x10(%ebx), %xmm4, %xmm5
	vpsrlq	$0x4, %xmm6, %xmm7
	vpsrlq	%xmm0, %ymm1, %ymm2
	vpsrlq	(%eax), %ymm3, %ymm4
	vpsrlq	0x10(%ebx), %ymm4, %ymm5
	vpsrlq	$0x4, %ymm6, %ymm7

	vpsrlw	%xmm0, %xmm1, %xmm2
	vpsrlw	(%eax), %xmm3, %xmm4
	vpsrlw	0x10(%ebx), %xmm4, %xmm5
	vpsrlw	$0x4, %xmm6, %xmm7
	vpsrlw	%xmm0, %ymm1, %ymm2
	vpsrlw	(%eax), %ymm3, %ymm4
	vpsrlw	0x10(%ebx), %ymm4, %ymm5
	vpsrlw	$0x4, %ymm6, %ymm7

	vpsubb	%xmm0, %xmm1, %xmm2
	vpsubb	(%eax), %xmm3, %xmm4
	vpsubb	0x42(%ecx), %xmm5, %xmm6
	vpsubb	%ymm0, %ymm1, %ymm2
	vpsubb	(%ebx), %ymm3, %ymm4
	vpsubb	0x42(%edx), %ymm5, %ymm6

	vpsubd	%xmm0, %xmm1, %xmm2
	vpsubd	(%eax), %xmm3, %xmm4
	vpsubd	0x42(%ecx), %xmm5, %xmm6
	vpsubd	%ymm0, %ymm1, %ymm2
	vpsubd	(%ebx), %ymm3, %ymm4
	vpsubd	0x42(%edx), %ymm5, %ymm6

	vpsubq	%xmm0, %xmm1, %xmm2
	vpsubq	(%eax), %xmm3, %xmm4
	vpsubq	0x42(%ecx), %xmm5, %xmm6
	vpsubq	%ymm0, %ymm1, %ymm2
	vpsubq	(%ebx), %ymm3, %ymm4
	vpsubq	0x42(%edx), %ymm5, %ymm6

	vpsubsb	%xmm0, %xmm1, %xmm2
	vpsubsb	(%eax), %xmm3, %xmm4
	vpsubsb	0x42(%ecx), %xmm5, %xmm6
	vpsubsb	%ymm0, %ymm1, %ymm2
	vpsubsb	(%ebx), %ymm3, %ymm4
	vpsubsb	0x42(%edx), %ymm5, %ymm6

	vpsubsw	%xmm0, %xmm1, %xmm2
	vpsubsw	(%eax), %xmm3, %xmm4
	vpsubsw	0x42(%ecx), %xmm5, %xmm6
	vpsubsw	%ymm0, %ymm1, %ymm2
	vpsubsw	(%ebx), %ymm3, %ymm4
	vpsubsw	0x42(%edx), %ymm5, %ymm6

	vpsubusb	%xmm0, %xmm1, %xmm2
	vpsubusb	(%eax), %xmm3, %xmm4
	vpsubusb	0x42(%ecx), %xmm5, %xmm6
	vpsubusb	%ymm0, %ymm1, %ymm2
	vpsubusb	(%ebx), %ymm3, %ymm4
	vpsubusb	0x42(%edx), %ymm5, %ymm6

	vpsubusw	%xmm0, %xmm1, %xmm2
	vpsubusw	(%eax), %xmm3, %xmm4
	vpsubusw	0x42(%ecx), %xmm5, %xmm6
	vpsubusw	%ymm0, %ymm1, %ymm2
	vpsubusw	(%ebx), %ymm3, %ymm4
	vpsubusw	0x42(%edx), %ymm5, %ymm6

	vpsubw	%xmm0, %xmm1, %xmm2
	vpsubw	(%eax), %xmm3, %xmm4
	vpsubw	0x42(%ecx), %xmm5, %xmm6
	vpsubw	%ymm0, %ymm1, %ymm2
	vpsubw	(%ebx), %ymm3, %ymm4
	vpsubw	0x42(%edx), %ymm5, %ymm6

	vptest	%xmm0, %xmm1
	vptest	(%esi), %xmm3
	vptest	0x42(%edi), %xmm3
	vptest	%ymm7, %ymm6
	vptest	(%ebp), %ymm4
	vptest	0x42(%esp), %ymm4

	vpunpckhbw	%xmm0, %xmm1, %xmm2
	vpunpckhbw	(%eax), %xmm3, %xmm4
	vpunpckhbw	0x42(%ecx), %xmm5, %xmm6
	vpunpckhbw	%ymm0, %ymm1, %ymm2
	vpunpckhbw	(%ebx), %ymm3, %ymm4
	vpunpckhbw	0x42(%edx), %ymm5, %ymm6

	vpunpckhdq	%xmm0, %xmm1, %xmm2
	vpunpckhdq	(%eax), %xmm3, %xmm4
	vpunpckhdq	0x42(%ecx), %xmm5, %xmm6
	vpunpckhdq	%ymm0, %ymm1, %ymm2
	vpunpckhdq	(%ebx), %ymm3, %ymm4
	vpunpckhdq	0x42(%edx), %ymm5, %ymm6

	vpunpckhqdq	%xmm0, %xmm1, %xmm2
	vpunpckhqdq	(%eax), %xmm3, %xmm4
	vpunpckhqdq	0x42(%ecx), %xmm5, %xmm6
	vpunpckhqdq	%ymm0, %ymm1, %ymm2
	vpunpckhqdq	(%ebx), %ymm3, %ymm4
	vpunpckhqdq	0x42(%edx), %ymm5, %ymm6

	vpunpckhwd	%xmm0, %xmm1, %xmm2
	vpunpckhwd	(%eax), %xmm3, %xmm4
	vpunpckhwd	0x42(%ecx), %xmm5, %xmm6
	vpunpckhwd	%ymm0, %ymm1, %ymm2
	vpunpckhwd	(%ebx), %ymm3, %ymm4
	vpunpckhwd	0x42(%edx), %ymm5, %ymm6

	vpunpcklbw	%xmm0, %xmm1, %xmm2
	vpunpcklbw	(%eax), %xmm3, %xmm4
	vpunpcklbw	0x42(%ecx), %xmm5, %xmm6
	vpunpcklbw	%ymm0, %ymm1, %ymm2
	vpunpcklbw	(%ebx), %ymm3, %ymm4
	vpunpcklbw	0x42(%edx), %ymm5, %ymm6

	vpunpckldq	%xmm0, %xmm1, %xmm2
	vpunpckldq	(%eax), %xmm3, %xmm4
	vpunpckldq	0x42(%ecx), %xmm5, %xmm6
	vpunpckldq	%ymm0, %ymm1, %ymm2
	vpunpckldq	(%ebx), %ymm3, %ymm4
	vpunpckldq	0x42(%edx), %ymm5, %ymm6

	vpunpcklqdq	%xmm0, %xmm1, %xmm2
	vpunpcklqdq	(%eax), %xmm3, %xmm4
	vpunpcklqdq	0x42(%ecx), %xmm5, %xmm6
	vpunpcklqdq	%ymm0, %ymm1, %ymm2
	vpunpcklqdq	(%ebx), %ymm3, %ymm4
	vpunpcklqdq	0x42(%edx), %ymm5, %ymm6

	vpunpcklwd	%xmm0, %xmm1, %xmm2
	vpunpcklwd	(%eax), %xmm3, %xmm4
	vpunpcklwd	0x42(%ecx), %xmm5, %xmm6
	vpunpcklwd	%ymm0, %ymm1, %ymm2
	vpunpcklwd	(%ebx), %ymm3, %ymm4
	vpunpcklwd	0x42(%edx), %ymm5, %ymm6

	vpxor	%xmm0, %xmm1, %xmm2
	vpxor	(%eax), %xmm3, %xmm4
	vpxor	0x42(%ecx), %xmm5, %xmm6
	vpxor	%ymm0, %ymm1, %ymm2
	vpxor	(%ebx), %ymm3, %ymm4
	vpxor	0x42(%edx), %ymm5, %ymm6

	vrcpps	%xmm0, %xmm1
	vrcpps	(%esi), %xmm3
	vrcpps	0x42(%edi), %xmm3
	vrcpps	%ymm7, %ymm6
	vrcpps	(%ebp), %ymm4
	vrcpps	0x42(%esp), %ymm4

	vrcpss	%xmm0, %xmm1, %xmm2
	vrcpss	(%eax), %xmm3, %xmm4
	vrcpss	0x42(%ecx), %xmm5, %xmm6

	vroundpd	$0x42, %xmm0, %xmm1
	vroundpd	$0x23, 	(%esi), %xmm3
	vroundpd	$0x42, 0x42(%edi), %xmm3
	vroundpd	$0x42, %ymm0, %ymm1
	vroundpd	$0x23, 	(%esi), %ymm3
	vroundpd	$0x42, 0x42(%edi), %ymm3

	vroundps	$0x42, %xmm0, %xmm1
	vroundps	$0x23, 	(%esi), %xmm3
	vroundps	$0x42, 0x42(%edi), %xmm3
	vroundps	$0x42, %ymm0, %ymm1
	vroundps	$0x23, 	(%esi), %ymm3
	vroundps	$0x42, 0x42(%edi), %ymm3

	vroundsd	$0x48, %xmm3, %xmm5, %xmm7
	vroundsd	$0x48, (%ebx), %xmm2, %xmm4
	vroundsd	$0x48, 0x8(%ebx), %xmm1, %xmm6

	vroundss	$0x48, %xmm3, %xmm5, %xmm7
	vroundss	$0x48, (%ebx), %xmm2, %xmm4
	vroundss	$0x48, 0x8(%ebx), %xmm1, %xmm6

	vrsqrtps	%xmm0, %xmm1
	vrsqrtps	(%esi), %xmm3
	vrsqrtps	0x42(%edi), %xmm3
	vrsqrtps	%ymm7, %ymm6
	vrsqrtps	(%ebp), %ymm4
	vrsqrtps	0x42(%esp), %ymm4

	vrsqrtss	%xmm0, %xmm1, %xmm2
	vrsqrtss	(%eax), %xmm3, %xmm4
	vrsqrtss	0x42(%ecx), %xmm5, %xmm6

	vshufpd	$0x48, %xmm3, %xmm5, %xmm7
	vshufpd	$0x48, (%ebx), %xmm2, %xmm4
	vshufpd	$0x48, 0x8(%ebx), %xmm1, %xmm6
	vshufpd	$0x48, %ymm3, %ymm5, %ymm7
	vshufpd	$0x48, (%ebx), %ymm2, %ymm4
	vshufpd	$0x48, 0x8(%ebx), %ymm1, %ymm6

	vshufps	$0x48, %xmm3, %xmm5, %xmm7
	vshufps	$0x48, (%ebx), %xmm2, %xmm4
	vshufps	$0x48, 0x8(%ebx), %xmm1, %xmm6
	vshufps	$0x48, %ymm3, %ymm5, %ymm7
	vshufps	$0x48, (%ebx), %ymm2, %ymm4
	vshufps	$0x48, 0x8(%ebx), %ymm1, %ymm6

	vsqrtpd	%xmm0, %xmm1
	vsqrtpd	(%esi), %xmm3
	vsqrtpd	0x42(%edi), %xmm3
	vsqrtpd	%ymm7, %ymm6
	vsqrtpd	(%ebp), %ymm4
	vsqrtpd	0x42(%esp), %ymm4

	vsqrtps	%xmm0, %xmm1
	vsqrtps	(%esi), %xmm3
	vsqrtps	0x42(%edi), %xmm3
	vsqrtps	%ymm7, %ymm6
	vsqrtps	(%ebp), %ymm4
	vsqrtps	0x42(%esp), %ymm4

	vsqrtsd	%xmm0, %xmm1, %xmm2
	vsqrtsd	(%eax), %xmm3, %xmm4
	vsqrtsd	0x42(%ecx), %xmm5, %xmm6

	vsqrtss	%xmm0, %xmm1, %xmm2
	vsqrtss	(%eax), %xmm3, %xmm4
	vsqrtss	0x42(%ecx), %xmm5, %xmm6

	vstmxcsr	(%edx)
	vstmxcsr	0x8(%edx)

	vsubpd	%xmm0, %xmm1, %xmm2
	vsubpd	(%eax), %xmm3, %xmm4
	vsubpd	0x42(%ecx), %xmm5, %xmm6
	vsubpd	%ymm0, %ymm1, %ymm2
	vsubpd	(%ebx), %ymm3, %ymm4
	vsubpd	0x42(%edx), %ymm5, %ymm6

	vsubps	%xmm0, %xmm1, %xmm2
	vsubps	(%eax), %xmm3, %xmm4
	vsubps	0x42(%ecx), %xmm5, %xmm6
	vsubps	%ymm0, %ymm1, %ymm2
	vsubps	(%ebx), %ymm3, %ymm4
	vsubps	0x42(%edx), %ymm5, %ymm6

	vsubsd	%xmm0, %xmm1, %xmm2
	vsubsd	(%eax), %xmm3, %xmm4
	vsubsd	0x42(%ecx), %xmm5, %xmm6

	vsubss	%xmm0, %xmm1, %xmm2
	vsubss	(%eax), %xmm3, %xmm4
	vsubss	0x42(%ecx), %xmm5, %xmm6

	vtestpd	%xmm0, %xmm1
	vtestpd	(%esi), %xmm3
	vtestpd	0x42(%edi), %xmm3
	vtestpd	%ymm7, %ymm6
	vtestpd	(%ebp), %ymm4
	vtestpd	0x42(%esp), %ymm4

	vtestps	%xmm0, %xmm1
	vtestps	(%esi), %xmm3
	vtestps	0x42(%edi), %xmm3
	vtestps	%ymm7, %ymm6
	vtestps	(%ebp), %ymm4
	vtestps	0x42(%esp), %ymm4

	vucomisd	%xmm0, %xmm1
	vucomisd	(%esi), %xmm3
	vucomisd	0x42(%edi), %xmm3

	vucomiss	%xmm0, %xmm1
	vucomiss	(%esi), %xmm3
	vucomiss	0x42(%edi), %xmm3

	vunpckhpd	%xmm0, %xmm1, %xmm2
	vunpckhpd	(%eax), %xmm3, %xmm4
	vunpckhpd	0x42(%ecx), %xmm5, %xmm6
	vunpckhpd	%ymm0, %ymm1, %ymm2
	vunpckhpd	(%ebx), %ymm3, %ymm4
	vunpckhpd	0x42(%edx), %ymm5, %ymm6

	vunpckhps	%xmm0, %xmm1, %xmm2
	vunpckhps	(%eax), %xmm3, %xmm4
	vunpckhps	0x42(%ecx), %xmm5, %xmm6
	vunpckhps	%ymm0, %ymm1, %ymm2
	vunpckhps	(%ebx), %ymm3, %ymm4
	vunpckhps	0x42(%edx), %ymm5, %ymm6

	vunpcklpd	%xmm0, %xmm1, %xmm2
	vunpcklpd	(%eax), %xmm3, %xmm4
	vunpcklpd	0x42(%ecx), %xmm5, %xmm6
	vunpcklpd	%ymm0, %ymm1, %ymm2
	vunpcklpd	(%ebx), %ymm3, %ymm4
	vunpcklpd	0x42(%edx), %ymm5, %ymm6

	vunpcklps	%xmm0, %xmm1, %xmm2
	vunpcklps	(%eax), %xmm3, %xmm4
	vunpcklps	0x42(%ecx), %xmm5, %xmm6
	vunpcklps	%ymm0, %ymm1, %ymm2
	vunpcklps	(%ebx), %ymm3, %ymm4
	vunpcklps	0x42(%edx), %ymm5, %ymm6

	vxorpd	%xmm0, %xmm1, %xmm2
	vxorpd	(%eax), %xmm3, %xmm4
	vxorpd	0x42(%ecx), %xmm5, %xmm6
	vxorpd	%ymm0, %ymm1, %ymm2
	vxorpd	(%ebx), %ymm3, %ymm4
	vxorpd	0x42(%edx), %ymm5, %ymm6

	vxorps	%xmm0, %xmm1, %xmm2
	vxorps	(%eax), %xmm3, %xmm4
	vxorps	0x42(%ecx), %xmm5, %xmm6
	vxorps	%ymm0, %ymm1, %ymm2
	vxorps	(%ebx), %ymm3, %ymm4
	vxorps	0x42(%edx), %ymm5, %ymm6

	vzeroall

	vzeroupper
.size libdis_test, [.-libdis_test]
