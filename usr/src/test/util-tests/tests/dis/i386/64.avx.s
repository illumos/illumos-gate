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
	vaddpd	(%rax), %xmm3, %xmm4
	vaddpd	0x42(%rcx), %xmm5, %xmm6
	vaddpd	%ymm0, %ymm1, %ymm2
	vaddpd	(%rbx), %ymm3, %ymm4
	vaddpd	0x42(%rdx), %ymm5, %ymm6

	vaddps	%xmm0, %xmm1, %xmm2
	vaddps	(%rax), %xmm3, %xmm4
	vaddps	0x42(%rcx), %xmm5, %xmm6
	vaddps	%ymm0, %ymm1, %ymm2
	vaddps	(%rbx), %ymm3, %ymm4
	vaddps	0x42(%rdx), %ymm5, %ymm6

	vaddsd	%xmm0, %xmm1, %xmm2
	vaddsd	(%rax), %xmm3, %xmm4
	vaddsd	0x42(%rcx), %xmm5, %xmm6

	vaddss	%xmm0, %xmm1, %xmm2
	vaddss	(%rax), %xmm3, %xmm4
	vaddss	0x42(%rcx), %xmm5, %xmm6

	vaddsubpd	%xmm0, %xmm1, %xmm2
	vaddsubpd	(%rax), %xmm3, %xmm4
	vaddsubpd	0x42(%rcx), %xmm5, %xmm6
	vaddsubpd	%ymm0, %ymm1, %ymm2
	vaddsubpd	(%rbx), %ymm3, %ymm4
	vaddsubpd	0x42(%rdx), %ymm5, %ymm6

	vaddsubps	%xmm0, %xmm1, %xmm2
	vaddsubps	(%rax), %xmm3, %xmm4
	vaddsubps	0x42(%rcx), %xmm5, %xmm6
	vaddsubps	%ymm0, %ymm1, %ymm2
	vaddsubps	(%rbx), %ymm3, %ymm4
	vaddsubps	0x42(%rdx), %ymm5, %ymm6

	vaesdec	%xmm0, %xmm1, %xmm2
	vaesdec	(%rax), %xmm3, %xmm4
	vaesdec	0x42(%rcx), %xmm5, %xmm6

	vaesdeclast	%xmm0, %xmm1, %xmm2
	vaesdeclast	(%rax), %xmm3, %xmm4
	vaesdeclast	0x42(%rcx), %xmm5, %xmm6

	vaesenc	%xmm0, %xmm1, %xmm2
	vaesenc	(%rax), %xmm3, %xmm4
	vaesenc	0x42(%rcx), %xmm5, %xmm6

	vaesenclast	%xmm0, %xmm1, %xmm2
	vaesenclast	(%rax), %xmm3, %xmm4
	vaesenclast	0x42(%rcx), %xmm5, %xmm6

	vaesimc	%xmm0, %xmm1
	vaesimc	(%rsi), %xmm3
	vaesimc	0x42(%rdi), %xmm3

	vaeskeygenassist	$0x42, %xmm0, %xmm1
	vaeskeygenassist	$0x23, 	(%rsi), %xmm3
	vaeskeygenassist	$0x42, 0x42(%rdi), %xmm3

	vandnpd	%xmm0, %xmm1, %xmm2
	vandnpd	(%rax), %xmm3, %xmm4
	vandnpd	0x42(%rcx), %xmm5, %xmm6
	vandnpd	%ymm0, %ymm1, %ymm2
	vandnpd	(%rbx), %ymm3, %ymm4
	vandnpd	0x42(%rdx), %ymm5, %ymm6

	vandnps	%xmm0, %xmm1, %xmm2
	vandnps	(%rax), %xmm3, %xmm4
	vandnps	0x42(%rcx), %xmm5, %xmm6
	vandnps	%ymm0, %ymm1, %ymm2
	vandnps	(%rbx), %ymm3, %ymm4
	vandnps	0x42(%rdx), %ymm5, %ymm6

	vandpd	%xmm0, %xmm1, %xmm2
	vandpd	(%rax), %xmm3, %xmm4
	vandpd	0x42(%rcx), %xmm5, %xmm6
	vandpd	%ymm0, %ymm1, %ymm2
	vandpd	(%rbx), %ymm3, %ymm4
	vandpd	0x42(%rdx), %ymm5, %ymm6

	vandps	%xmm0, %xmm1, %xmm2
	vandps	(%rax), %xmm3, %xmm4
	vandps	0x42(%rcx), %xmm5, %xmm6
	vandps	%ymm0, %ymm1, %ymm2
	vandps	(%rbx), %ymm3, %ymm4
	vandps	0x42(%rdx), %ymm5, %ymm6

	vblendpd	$0x48, %xmm3, %xmm5, %xmm7
	vblendpd	$0x48, (%rbx), %xmm2, %xmm4
	vblendpd	$0x48, 0x8(%rbx), %xmm1, %xmm6
	vblendpd	$0x48, %ymm3, %ymm5, %ymm7
	vblendpd	$0x48, (%rbx), %ymm2, %ymm4
	vblendpd	$0x48, 0x8(%rbx), %ymm1, %ymm6

	vblendps	$0x48, %xmm3, %xmm5, %xmm7
	vblendps	$0x48, (%rbx), %xmm2, %xmm4
	vblendps	$0x48, 0x8(%rbx), %xmm1, %xmm6
	vblendps	$0x48, %ymm3, %ymm5, %ymm7
	vblendps	$0x48, (%rbx), %ymm2, %ymm4
	vblendps	$0x48, 0x8(%rbx), %ymm1, %ymm6

	vblendvpd	%xmm0, %xmm1, %xmm2, %xmm3
	vblendvpd	%xmm0, (%rax), %xmm2, %xmm3
	vblendvpd	%xmm0, 0x10(%rbx), %xmm2, %xmm3
	vblendvpd	%ymm0, %ymm1, %ymm2, %ymm3
	vblendvpd	%ymm0, (%rax), %ymm2, %ymm3
	vblendvpd	%ymm0, 0x10(%rbx), %ymm2, %ymm3

	vblendvps	%xmm0, %xmm1, %xmm2, %xmm3
	vblendvps	%xmm0, (%rax), %xmm2, %xmm3
	vblendvps	%xmm0, 0x10(%rbx), %xmm2, %xmm3
	vblendvps	%ymm0, %ymm1, %ymm2, %ymm3
	vblendvps	%ymm0, (%rax), %ymm2, %ymm3
	vblendvps	%ymm0, 0x10(%rbx), %ymm2, %ymm3

	vbroadcastf128	(%rax), %ymm0
	vbroadcastf128	0x42(%rax), %ymm0

	vbroadcastsd	(%rax), %ymm0
	vbroadcastsd	0x42(%rax), %ymm0

	vbroadcastss	(%rax), %ymm0
	vbroadcastss	0x42(%rax), %ymm0

	vcmpeq_ospd	%xmm0, %xmm1, %xmm2
	vcmpeq_ospd	(%rax), %xmm3, %xmm4
	vcmpeq_ospd	0x42(%rcx), %xmm5, %xmm6
	vcmpeq_ospd	%ymm0, %ymm1, %ymm2
	vcmpeq_ospd	(%rbx), %ymm3, %ymm4
	vcmpeq_ospd	0x42(%rdx), %ymm5, %ymm6

	vcmpeq_osps	%xmm0, %xmm1, %xmm2
	vcmpeq_osps	(%rax), %xmm3, %xmm4
	vcmpeq_osps	0x42(%rcx), %xmm5, %xmm6
	vcmpeq_osps	%ymm0, %ymm1, %ymm2
	vcmpeq_osps	(%rbx), %ymm3, %ymm4
	vcmpeq_osps	0x42(%rdx), %ymm5, %ymm6

	vcmpeq_ossd	%xmm0, %xmm1, %xmm2
	vcmpeq_ossd	(%rax), %xmm3, %xmm4
	vcmpeq_ossd	0x42(%rcx), %xmm5, %xmm6

	vcmpeq_osss	%xmm0, %xmm1, %xmm2
	vcmpeq_osss	(%rax), %xmm3, %xmm4
	vcmpeq_osss	0x42(%rcx), %xmm5, %xmm6

	vcmpeq_uqpd	%xmm0, %xmm1, %xmm2
	vcmpeq_uqpd	(%rax), %xmm3, %xmm4
	vcmpeq_uqpd	0x42(%rcx), %xmm5, %xmm6
	vcmpeq_uqpd	%ymm0, %ymm1, %ymm2
	vcmpeq_uqpd	(%rbx), %ymm3, %ymm4
	vcmpeq_uqpd	0x42(%rdx), %ymm5, %ymm6

	vcmpeq_uqps	%xmm0, %xmm1, %xmm2
	vcmpeq_uqps	(%rax), %xmm3, %xmm4
	vcmpeq_uqps	0x42(%rcx), %xmm5, %xmm6
	vcmpeq_uqps	%ymm0, %ymm1, %ymm2
	vcmpeq_uqps	(%rbx), %ymm3, %ymm4
	vcmpeq_uqps	0x42(%rdx), %ymm5, %ymm6

	vcmpeq_uqsd	%xmm0, %xmm1, %xmm2
	vcmpeq_uqsd	(%rax), %xmm3, %xmm4
	vcmpeq_uqsd	0x42(%rcx), %xmm5, %xmm6

	vcmpeq_uqss	%xmm0, %xmm1, %xmm2
	vcmpeq_uqss	(%rax), %xmm3, %xmm4
	vcmpeq_uqss	0x42(%rcx), %xmm5, %xmm6

	vcmpeq_uspd	%xmm0, %xmm1, %xmm2
	vcmpeq_uspd	(%rax), %xmm3, %xmm4
	vcmpeq_uspd	0x42(%rcx), %xmm5, %xmm6
	vcmpeq_uspd	%ymm0, %ymm1, %ymm2
	vcmpeq_uspd	(%rbx), %ymm3, %ymm4
	vcmpeq_uspd	0x42(%rdx), %ymm5, %ymm6

	vcmpeq_usps	%xmm0, %xmm1, %xmm2
	vcmpeq_usps	(%rax), %xmm3, %xmm4
	vcmpeq_usps	0x42(%rcx), %xmm5, %xmm6
	vcmpeq_usps	%ymm0, %ymm1, %ymm2
	vcmpeq_usps	(%rbx), %ymm3, %ymm4
	vcmpeq_usps	0x42(%rdx), %ymm5, %ymm6

	vcmpeq_ussd	%xmm0, %xmm1, %xmm2
	vcmpeq_ussd	(%rax), %xmm3, %xmm4
	vcmpeq_ussd	0x42(%rcx), %xmm5, %xmm6

	vcmpeq_usss	%xmm0, %xmm1, %xmm2
	vcmpeq_usss	(%rax), %xmm3, %xmm4
	vcmpeq_usss	0x42(%rcx), %xmm5, %xmm6

	vcmpeqpd	%xmm0, %xmm1, %xmm2
	vcmpeqpd	(%rax), %xmm3, %xmm4
	vcmpeqpd	0x42(%rcx), %xmm5, %xmm6
	vcmpeqpd	%ymm0, %ymm1, %ymm2
	vcmpeqpd	(%rbx), %ymm3, %ymm4
	vcmpeqpd	0x42(%rdx), %ymm5, %ymm6

	vcmpeqps	%xmm0, %xmm1, %xmm2
	vcmpeqps	(%rax), %xmm3, %xmm4
	vcmpeqps	0x42(%rcx), %xmm5, %xmm6
	vcmpeqps	%ymm0, %ymm1, %ymm2
	vcmpeqps	(%rbx), %ymm3, %ymm4
	vcmpeqps	0x42(%rdx), %ymm5, %ymm6

	vcmpeqsd	%xmm0, %xmm1, %xmm2
	vcmpeqsd	(%rax), %xmm3, %xmm4
	vcmpeqsd	0x42(%rcx), %xmm5, %xmm6

	vcmpeqss	%xmm0, %xmm1, %xmm2
	vcmpeqss	(%rax), %xmm3, %xmm4
	vcmpeqss	0x42(%rcx), %xmm5, %xmm6

	vcmpfalse_ospd	%xmm0, %xmm1, %xmm2
	vcmpfalse_ospd	(%rax), %xmm3, %xmm4
	vcmpfalse_ospd	0x42(%rcx), %xmm5, %xmm6
	vcmpfalse_ospd	%ymm0, %ymm1, %ymm2
	vcmpfalse_ospd	(%rbx), %ymm3, %ymm4
	vcmpfalse_ospd	0x42(%rdx), %ymm5, %ymm6

	vcmpfalse_osps	%xmm0, %xmm1, %xmm2
	vcmpfalse_osps	(%rax), %xmm3, %xmm4
	vcmpfalse_osps	0x42(%rcx), %xmm5, %xmm6
	vcmpfalse_osps	%ymm0, %ymm1, %ymm2
	vcmpfalse_osps	(%rbx), %ymm3, %ymm4
	vcmpfalse_osps	0x42(%rdx), %ymm5, %ymm6

	vcmpfalse_ossd	%xmm0, %xmm1, %xmm2
	vcmpfalse_ossd	(%rax), %xmm3, %xmm4
	vcmpfalse_ossd	0x42(%rcx), %xmm5, %xmm6

	vcmpfalse_osss	%xmm0, %xmm1, %xmm2
	vcmpfalse_osss	(%rax), %xmm3, %xmm4
	vcmpfalse_osss	0x42(%rcx), %xmm5, %xmm6

	vcmpfalsepd	%xmm0, %xmm1, %xmm2
	vcmpfalsepd	(%rax), %xmm3, %xmm4
	vcmpfalsepd	0x42(%rcx), %xmm5, %xmm6
	vcmpfalsepd	%ymm0, %ymm1, %ymm2
	vcmpfalsepd	(%rbx), %ymm3, %ymm4
	vcmpfalsepd	0x42(%rdx), %ymm5, %ymm6

	vcmpfalseps	%xmm0, %xmm1, %xmm2
	vcmpfalseps	(%rax), %xmm3, %xmm4
	vcmpfalseps	0x42(%rcx), %xmm5, %xmm6
	vcmpfalseps	%ymm0, %ymm1, %ymm2
	vcmpfalseps	(%rbx), %ymm3, %ymm4
	vcmpfalseps	0x42(%rdx), %ymm5, %ymm6

	vcmpfalsesd	%xmm0, %xmm1, %xmm2
	vcmpfalsesd	(%rax), %xmm3, %xmm4
	vcmpfalsesd	0x42(%rcx), %xmm5, %xmm6

	vcmpfalsess	%xmm0, %xmm1, %xmm2
	vcmpfalsess	(%rax), %xmm3, %xmm4
	vcmpfalsess	0x42(%rcx), %xmm5, %xmm6

	vcmpge_oqpd	%xmm0, %xmm1, %xmm2
	vcmpge_oqpd	(%rax), %xmm3, %xmm4
	vcmpge_oqpd	0x42(%rcx), %xmm5, %xmm6
	vcmpge_oqpd	%ymm0, %ymm1, %ymm2
	vcmpge_oqpd	(%rbx), %ymm3, %ymm4
	vcmpge_oqpd	0x42(%rdx), %ymm5, %ymm6

	vcmpge_oqps	%xmm0, %xmm1, %xmm2
	vcmpge_oqps	(%rax), %xmm3, %xmm4
	vcmpge_oqps	0x42(%rcx), %xmm5, %xmm6
	vcmpge_oqps	%ymm0, %ymm1, %ymm2
	vcmpge_oqps	(%rbx), %ymm3, %ymm4
	vcmpge_oqps	0x42(%rdx), %ymm5, %ymm6

	vcmpge_oqsd	%xmm0, %xmm1, %xmm2
	vcmpge_oqsd	(%rax), %xmm3, %xmm4
	vcmpge_oqsd	0x42(%rcx), %xmm5, %xmm6

	vcmpge_oqss	%xmm0, %xmm1, %xmm2
	vcmpge_oqss	(%rax), %xmm3, %xmm4
	vcmpge_oqss	0x42(%rcx), %xmm5, %xmm6

	vcmpgepd	%xmm0, %xmm1, %xmm2
	vcmpgepd	(%rax), %xmm3, %xmm4
	vcmpgepd	0x42(%rcx), %xmm5, %xmm6
	vcmpgepd	%ymm0, %ymm1, %ymm2
	vcmpgepd	(%rbx), %ymm3, %ymm4
	vcmpgepd	0x42(%rdx), %ymm5, %ymm6

	vcmpgeps	%xmm0, %xmm1, %xmm2
	vcmpgeps	(%rax), %xmm3, %xmm4
	vcmpgeps	0x42(%rcx), %xmm5, %xmm6
	vcmpgeps	%ymm0, %ymm1, %ymm2
	vcmpgeps	(%rbx), %ymm3, %ymm4
	vcmpgeps	0x42(%rdx), %ymm5, %ymm6

	vcmpgesd	%xmm0, %xmm1, %xmm2
	vcmpgesd	(%rax), %xmm3, %xmm4
	vcmpgesd	0x42(%rcx), %xmm5, %xmm6

	vcmpgess	%xmm0, %xmm1, %xmm2
	vcmpgess	(%rax), %xmm3, %xmm4
	vcmpgess	0x42(%rcx), %xmm5, %xmm6

	vcmpgt_oqpd	%xmm0, %xmm1, %xmm2
	vcmpgt_oqpd	(%rax), %xmm3, %xmm4
	vcmpgt_oqpd	0x42(%rcx), %xmm5, %xmm6
	vcmpgt_oqpd	%ymm0, %ymm1, %ymm2
	vcmpgt_oqpd	(%rbx), %ymm3, %ymm4
	vcmpgt_oqpd	0x42(%rdx), %ymm5, %ymm6

	vcmpgt_oqps	%xmm0, %xmm1, %xmm2
	vcmpgt_oqps	(%rax), %xmm3, %xmm4
	vcmpgt_oqps	0x42(%rcx), %xmm5, %xmm6
	vcmpgt_oqps	%ymm0, %ymm1, %ymm2
	vcmpgt_oqps	(%rbx), %ymm3, %ymm4
	vcmpgt_oqps	0x42(%rdx), %ymm5, %ymm6

	vcmpgt_oqsd	%xmm0, %xmm1, %xmm2
	vcmpgt_oqsd	(%rax), %xmm3, %xmm4
	vcmpgt_oqsd	0x42(%rcx), %xmm5, %xmm6

	vcmpgt_oqss	%xmm0, %xmm1, %xmm2
	vcmpgt_oqss	(%rax), %xmm3, %xmm4
	vcmpgt_oqss	0x42(%rcx), %xmm5, %xmm6

	vcmpgtpd	%xmm0, %xmm1, %xmm2
	vcmpgtpd	(%rax), %xmm3, %xmm4
	vcmpgtpd	0x42(%rcx), %xmm5, %xmm6
	vcmpgtpd	%ymm0, %ymm1, %ymm2
	vcmpgtpd	(%rbx), %ymm3, %ymm4
	vcmpgtpd	0x42(%rdx), %ymm5, %ymm6

	vcmpgtps	%xmm0, %xmm1, %xmm2
	vcmpgtps	(%rax), %xmm3, %xmm4
	vcmpgtps	0x42(%rcx), %xmm5, %xmm6
	vcmpgtps	%ymm0, %ymm1, %ymm2
	vcmpgtps	(%rbx), %ymm3, %ymm4
	vcmpgtps	0x42(%rdx), %ymm5, %ymm6

	vcmpgtsd	%xmm0, %xmm1, %xmm2
	vcmpgtsd	(%rax), %xmm3, %xmm4
	vcmpgtsd	0x42(%rcx), %xmm5, %xmm6

	vcmpgtss	%xmm0, %xmm1, %xmm2
	vcmpgtss	(%rax), %xmm3, %xmm4
	vcmpgtss	0x42(%rcx), %xmm5, %xmm6

	vcmple_oqpd	%xmm0, %xmm1, %xmm2
	vcmple_oqpd	(%rax), %xmm3, %xmm4
	vcmple_oqpd	0x42(%rcx), %xmm5, %xmm6
	vcmple_oqpd	%ymm0, %ymm1, %ymm2
	vcmple_oqpd	(%rbx), %ymm3, %ymm4
	vcmple_oqpd	0x42(%rdx), %ymm5, %ymm6

	vcmple_oqps	%xmm0, %xmm1, %xmm2
	vcmple_oqps	(%rax), %xmm3, %xmm4
	vcmple_oqps	0x42(%rcx), %xmm5, %xmm6
	vcmple_oqps	%ymm0, %ymm1, %ymm2
	vcmple_oqps	(%rbx), %ymm3, %ymm4
	vcmple_oqps	0x42(%rdx), %ymm5, %ymm6

	vcmple_oqsd	%xmm0, %xmm1, %xmm2
	vcmple_oqsd	(%rax), %xmm3, %xmm4
	vcmple_oqsd	0x42(%rcx), %xmm5, %xmm6

	vcmple_oqss	%xmm0, %xmm1, %xmm2
	vcmple_oqss	(%rax), %xmm3, %xmm4
	vcmple_oqss	0x42(%rcx), %xmm5, %xmm6

	vcmplepd	%xmm0, %xmm1, %xmm2
	vcmplepd	(%rax), %xmm3, %xmm4
	vcmplepd	0x42(%rcx), %xmm5, %xmm6
	vcmplepd	%ymm0, %ymm1, %ymm2
	vcmplepd	(%rbx), %ymm3, %ymm4
	vcmplepd	0x42(%rdx), %ymm5, %ymm6

	vcmpleps	%xmm0, %xmm1, %xmm2
	vcmpleps	(%rax), %xmm3, %xmm4
	vcmpleps	0x42(%rcx), %xmm5, %xmm6
	vcmpleps	%ymm0, %ymm1, %ymm2
	vcmpleps	(%rbx), %ymm3, %ymm4
	vcmpleps	0x42(%rdx), %ymm5, %ymm6

	vcmplesd	%xmm0, %xmm1, %xmm2
	vcmplesd	(%rax), %xmm3, %xmm4
	vcmplesd	0x42(%rcx), %xmm5, %xmm6

	vcmpless	%xmm0, %xmm1, %xmm2
	vcmpless	(%rax), %xmm3, %xmm4
	vcmpless	0x42(%rcx), %xmm5, %xmm6

	vcmplt_oqpd	%xmm0, %xmm1, %xmm2
	vcmplt_oqpd	(%rax), %xmm3, %xmm4
	vcmplt_oqpd	0x42(%rcx), %xmm5, %xmm6
	vcmplt_oqpd	%ymm0, %ymm1, %ymm2
	vcmplt_oqpd	(%rbx), %ymm3, %ymm4
	vcmplt_oqpd	0x42(%rdx), %ymm5, %ymm6

	vcmplt_oqps	%xmm0, %xmm1, %xmm2
	vcmplt_oqps	(%rax), %xmm3, %xmm4
	vcmplt_oqps	0x42(%rcx), %xmm5, %xmm6
	vcmplt_oqps	%ymm0, %ymm1, %ymm2
	vcmplt_oqps	(%rbx), %ymm3, %ymm4
	vcmplt_oqps	0x42(%rdx), %ymm5, %ymm6

	vcmplt_oqsd	%xmm0, %xmm1, %xmm2
	vcmplt_oqsd	(%rax), %xmm3, %xmm4
	vcmplt_oqsd	0x42(%rcx), %xmm5, %xmm6

	vcmplt_oqss	%xmm0, %xmm1, %xmm2
	vcmplt_oqss	(%rax), %xmm3, %xmm4
	vcmplt_oqss	0x42(%rcx), %xmm5, %xmm6

	vcmpltpd	%xmm0, %xmm1, %xmm2
	vcmpltpd	(%rax), %xmm3, %xmm4
	vcmpltpd	0x42(%rcx), %xmm5, %xmm6
	vcmpltpd	%ymm0, %ymm1, %ymm2
	vcmpltpd	(%rbx), %ymm3, %ymm4
	vcmpltpd	0x42(%rdx), %ymm5, %ymm6

	vcmpltps	%xmm0, %xmm1, %xmm2
	vcmpltps	(%rax), %xmm3, %xmm4
	vcmpltps	0x42(%rcx), %xmm5, %xmm6
	vcmpltps	%ymm0, %ymm1, %ymm2
	vcmpltps	(%rbx), %ymm3, %ymm4
	vcmpltps	0x42(%rdx), %ymm5, %ymm6

	vcmpltsd	%xmm0, %xmm1, %xmm2
	vcmpltsd	(%rax), %xmm3, %xmm4
	vcmpltsd	0x42(%rcx), %xmm5, %xmm6

	vcmpltss	%xmm0, %xmm1, %xmm2
	vcmpltss	(%rax), %xmm3, %xmm4
	vcmpltss	0x42(%rcx), %xmm5, %xmm6

	vcmpneq_oqpd	%xmm0, %xmm1, %xmm2
	vcmpneq_oqpd	(%rax), %xmm3, %xmm4
	vcmpneq_oqpd	0x42(%rcx), %xmm5, %xmm6
	vcmpneq_oqpd	%ymm0, %ymm1, %ymm2
	vcmpneq_oqpd	(%rbx), %ymm3, %ymm4
	vcmpneq_oqpd	0x42(%rdx), %ymm5, %ymm6

	vcmpneq_oqps	%xmm0, %xmm1, %xmm2
	vcmpneq_oqps	(%rax), %xmm3, %xmm4
	vcmpneq_oqps	0x42(%rcx), %xmm5, %xmm6
	vcmpneq_oqps	%ymm0, %ymm1, %ymm2
	vcmpneq_oqps	(%rbx), %ymm3, %ymm4
	vcmpneq_oqps	0x42(%rdx), %ymm5, %ymm6

	vcmpneq_oqsd	%xmm0, %xmm1, %xmm2
	vcmpneq_oqsd	(%rax), %xmm3, %xmm4
	vcmpneq_oqsd	0x42(%rcx), %xmm5, %xmm6

	vcmpneq_oqss	%xmm0, %xmm1, %xmm2
	vcmpneq_oqss	(%rax), %xmm3, %xmm4
	vcmpneq_oqss	0x42(%rcx), %xmm5, %xmm6

	vcmpneq_ospd	%xmm0, %xmm1, %xmm2
	vcmpneq_ospd	(%rax), %xmm3, %xmm4
	vcmpneq_ospd	0x42(%rcx), %xmm5, %xmm6
	vcmpneq_ospd	%ymm0, %ymm1, %ymm2
	vcmpneq_ospd	(%rbx), %ymm3, %ymm4
	vcmpneq_ospd	0x42(%rdx), %ymm5, %ymm6

	vcmpneq_osps	%xmm0, %xmm1, %xmm2
	vcmpneq_osps	(%rax), %xmm3, %xmm4
	vcmpneq_osps	0x42(%rcx), %xmm5, %xmm6
	vcmpneq_osps	%ymm0, %ymm1, %ymm2
	vcmpneq_osps	(%rbx), %ymm3, %ymm4
	vcmpneq_osps	0x42(%rdx), %ymm5, %ymm6

	vcmpneq_ossd	%xmm0, %xmm1, %xmm2
	vcmpneq_ossd	(%rax), %xmm3, %xmm4
	vcmpneq_ossd	0x42(%rcx), %xmm5, %xmm6

	vcmpneq_osss	%xmm0, %xmm1, %xmm2
	vcmpneq_osss	(%rax), %xmm3, %xmm4
	vcmpneq_osss	0x42(%rcx), %xmm5, %xmm6

	vcmpneq_uspd	%xmm0, %xmm1, %xmm2
	vcmpneq_uspd	(%rax), %xmm3, %xmm4
	vcmpneq_uspd	0x42(%rcx), %xmm5, %xmm6
	vcmpneq_uspd	%ymm0, %ymm1, %ymm2
	vcmpneq_uspd	(%rbx), %ymm3, %ymm4
	vcmpneq_uspd	0x42(%rdx), %ymm5, %ymm6

	vcmpneq_usps	%xmm0, %xmm1, %xmm2
	vcmpneq_usps	(%rax), %xmm3, %xmm4
	vcmpneq_usps	0x42(%rcx), %xmm5, %xmm6
	vcmpneq_usps	%ymm0, %ymm1, %ymm2
	vcmpneq_usps	(%rbx), %ymm3, %ymm4
	vcmpneq_usps	0x42(%rdx), %ymm5, %ymm6

	vcmpneq_ussd	%xmm0, %xmm1, %xmm2
	vcmpneq_ussd	(%rax), %xmm3, %xmm4
	vcmpneq_ussd	0x42(%rcx), %xmm5, %xmm6

	vcmpneq_usss	%xmm0, %xmm1, %xmm2
	vcmpneq_usss	(%rax), %xmm3, %xmm4
	vcmpneq_usss	0x42(%rcx), %xmm5, %xmm6

	vcmpneqpd	%xmm0, %xmm1, %xmm2
	vcmpneqpd	(%rax), %xmm3, %xmm4
	vcmpneqpd	0x42(%rcx), %xmm5, %xmm6
	vcmpneqpd	%ymm0, %ymm1, %ymm2
	vcmpneqpd	(%rbx), %ymm3, %ymm4
	vcmpneqpd	0x42(%rdx), %ymm5, %ymm6

	vcmpneqps	%xmm0, %xmm1, %xmm2
	vcmpneqps	(%rax), %xmm3, %xmm4
	vcmpneqps	0x42(%rcx), %xmm5, %xmm6
	vcmpneqps	%ymm0, %ymm1, %ymm2
	vcmpneqps	(%rbx), %ymm3, %ymm4
	vcmpneqps	0x42(%rdx), %ymm5, %ymm6

	vcmpneqsd	%xmm0, %xmm1, %xmm2
	vcmpneqsd	(%rax), %xmm3, %xmm4
	vcmpneqsd	0x42(%rcx), %xmm5, %xmm6

	vcmpneqss	%xmm0, %xmm1, %xmm2
	vcmpneqss	(%rax), %xmm3, %xmm4
	vcmpneqss	0x42(%rcx), %xmm5, %xmm6

	vcmpnge_uqpd	%xmm0, %xmm1, %xmm2
	vcmpnge_uqpd	(%rax), %xmm3, %xmm4
	vcmpnge_uqpd	0x42(%rcx), %xmm5, %xmm6
	vcmpnge_uqpd	%ymm0, %ymm1, %ymm2
	vcmpnge_uqpd	(%rbx), %ymm3, %ymm4
	vcmpnge_uqpd	0x42(%rdx), %ymm5, %ymm6

	vcmpnge_uqps	%xmm0, %xmm1, %xmm2
	vcmpnge_uqps	(%rax), %xmm3, %xmm4
	vcmpnge_uqps	0x42(%rcx), %xmm5, %xmm6
	vcmpnge_uqps	%ymm0, %ymm1, %ymm2
	vcmpnge_uqps	(%rbx), %ymm3, %ymm4
	vcmpnge_uqps	0x42(%rdx), %ymm5, %ymm6

	vcmpnge_uqsd	%xmm0, %xmm1, %xmm2
	vcmpnge_uqsd	(%rax), %xmm3, %xmm4
	vcmpnge_uqsd	0x42(%rcx), %xmm5, %xmm6

	vcmpnge_uqss	%xmm0, %xmm1, %xmm2
	vcmpnge_uqss	(%rax), %xmm3, %xmm4
	vcmpnge_uqss	0x42(%rcx), %xmm5, %xmm6

	vcmpngepd	%xmm0, %xmm1, %xmm2
	vcmpngepd	(%rax), %xmm3, %xmm4
	vcmpngepd	0x42(%rcx), %xmm5, %xmm6
	vcmpngepd	%ymm0, %ymm1, %ymm2
	vcmpngepd	(%rbx), %ymm3, %ymm4
	vcmpngepd	0x42(%rdx), %ymm5, %ymm6

	vcmpngeps	%xmm0, %xmm1, %xmm2
	vcmpngeps	(%rax), %xmm3, %xmm4
	vcmpngeps	0x42(%rcx), %xmm5, %xmm6
	vcmpngeps	%ymm0, %ymm1, %ymm2
	vcmpngeps	(%rbx), %ymm3, %ymm4
	vcmpngeps	0x42(%rdx), %ymm5, %ymm6

	vcmpngesd	%xmm0, %xmm1, %xmm2
	vcmpngesd	(%rax), %xmm3, %xmm4
	vcmpngesd	0x42(%rcx), %xmm5, %xmm6

	vcmpngess	%xmm0, %xmm1, %xmm2
	vcmpngess	(%rax), %xmm3, %xmm4
	vcmpngess	0x42(%rcx), %xmm5, %xmm6

	vcmpngt_uqpd	%xmm0, %xmm1, %xmm2
	vcmpngt_uqpd	(%rax), %xmm3, %xmm4
	vcmpngt_uqpd	0x42(%rcx), %xmm5, %xmm6
	vcmpngt_uqpd	%ymm0, %ymm1, %ymm2
	vcmpngt_uqpd	(%rbx), %ymm3, %ymm4
	vcmpngt_uqpd	0x42(%rdx), %ymm5, %ymm6

	vcmpngt_uqps	%xmm0, %xmm1, %xmm2
	vcmpngt_uqps	(%rax), %xmm3, %xmm4
	vcmpngt_uqps	0x42(%rcx), %xmm5, %xmm6
	vcmpngt_uqps	%ymm0, %ymm1, %ymm2
	vcmpngt_uqps	(%rbx), %ymm3, %ymm4
	vcmpngt_uqps	0x42(%rdx), %ymm5, %ymm6

	vcmpngt_uqsd	%xmm0, %xmm1, %xmm2
	vcmpngt_uqsd	(%rax), %xmm3, %xmm4
	vcmpngt_uqsd	0x42(%rcx), %xmm5, %xmm6

	vcmpngt_uqss	%xmm0, %xmm1, %xmm2
	vcmpngt_uqss	(%rax), %xmm3, %xmm4
	vcmpngt_uqss	0x42(%rcx), %xmm5, %xmm6

	vcmpngtpd	%xmm0, %xmm1, %xmm2
	vcmpngtpd	(%rax), %xmm3, %xmm4
	vcmpngtpd	0x42(%rcx), %xmm5, %xmm6
	vcmpngtpd	%ymm0, %ymm1, %ymm2
	vcmpngtpd	(%rbx), %ymm3, %ymm4
	vcmpngtpd	0x42(%rdx), %ymm5, %ymm6

	vcmpngtps	%xmm0, %xmm1, %xmm2
	vcmpngtps	(%rax), %xmm3, %xmm4
	vcmpngtps	0x42(%rcx), %xmm5, %xmm6
	vcmpngtps	%ymm0, %ymm1, %ymm2
	vcmpngtps	(%rbx), %ymm3, %ymm4
	vcmpngtps	0x42(%rdx), %ymm5, %ymm6

	vcmpngtsd	%xmm0, %xmm1, %xmm2
	vcmpngtsd	(%rax), %xmm3, %xmm4
	vcmpngtsd	0x42(%rcx), %xmm5, %xmm6

	vcmpngtss	%xmm0, %xmm1, %xmm2
	vcmpngtss	(%rax), %xmm3, %xmm4
	vcmpngtss	0x42(%rcx), %xmm5, %xmm6

	vcmpnle_uqpd	%xmm0, %xmm1, %xmm2
	vcmpnle_uqpd	(%rax), %xmm3, %xmm4
	vcmpnle_uqpd	0x42(%rcx), %xmm5, %xmm6
	vcmpnle_uqpd	%ymm0, %ymm1, %ymm2
	vcmpnle_uqpd	(%rbx), %ymm3, %ymm4
	vcmpnle_uqpd	0x42(%rdx), %ymm5, %ymm6

	vcmpnle_uqps	%xmm0, %xmm1, %xmm2
	vcmpnle_uqps	(%rax), %xmm3, %xmm4
	vcmpnle_uqps	0x42(%rcx), %xmm5, %xmm6
	vcmpnle_uqps	%ymm0, %ymm1, %ymm2
	vcmpnle_uqps	(%rbx), %ymm3, %ymm4
	vcmpnle_uqps	0x42(%rdx), %ymm5, %ymm6

	vcmpnle_uqsd	%xmm0, %xmm1, %xmm2
	vcmpnle_uqsd	(%rax), %xmm3, %xmm4
	vcmpnle_uqsd	0x42(%rcx), %xmm5, %xmm6

	vcmpnle_uqss	%xmm0, %xmm1, %xmm2
	vcmpnle_uqss	(%rax), %xmm3, %xmm4
	vcmpnle_uqss	0x42(%rcx), %xmm5, %xmm6

	vcmpnlepd	%xmm0, %xmm1, %xmm2
	vcmpnlepd	(%rax), %xmm3, %xmm4
	vcmpnlepd	0x42(%rcx), %xmm5, %xmm6
	vcmpnlepd	%ymm0, %ymm1, %ymm2
	vcmpnlepd	(%rbx), %ymm3, %ymm4
	vcmpnlepd	0x42(%rdx), %ymm5, %ymm6

	vcmpnleps	%xmm0, %xmm1, %xmm2
	vcmpnleps	(%rax), %xmm3, %xmm4
	vcmpnleps	0x42(%rcx), %xmm5, %xmm6
	vcmpnleps	%ymm0, %ymm1, %ymm2
	vcmpnleps	(%rbx), %ymm3, %ymm4
	vcmpnleps	0x42(%rdx), %ymm5, %ymm6

	vcmpnlesd	%xmm0, %xmm1, %xmm2
	vcmpnlesd	(%rax), %xmm3, %xmm4
	vcmpnlesd	0x42(%rcx), %xmm5, %xmm6

	vcmpnless	%xmm0, %xmm1, %xmm2
	vcmpnless	(%rax), %xmm3, %xmm4
	vcmpnless	0x42(%rcx), %xmm5, %xmm6

	vcmpnlt_uqpd	%xmm0, %xmm1, %xmm2
	vcmpnlt_uqpd	(%rax), %xmm3, %xmm4
	vcmpnlt_uqpd	0x42(%rcx), %xmm5, %xmm6
	vcmpnlt_uqpd	%ymm0, %ymm1, %ymm2
	vcmpnlt_uqpd	(%rbx), %ymm3, %ymm4
	vcmpnlt_uqpd	0x42(%rdx), %ymm5, %ymm6

	vcmpnlt_uqps	%xmm0, %xmm1, %xmm2
	vcmpnlt_uqps	(%rax), %xmm3, %xmm4
	vcmpnlt_uqps	0x42(%rcx), %xmm5, %xmm6
	vcmpnlt_uqps	%ymm0, %ymm1, %ymm2
	vcmpnlt_uqps	(%rbx), %ymm3, %ymm4
	vcmpnlt_uqps	0x42(%rdx), %ymm5, %ymm6

	vcmpnlt_uqsd	%xmm0, %xmm1, %xmm2
	vcmpnlt_uqsd	(%rax), %xmm3, %xmm4
	vcmpnlt_uqsd	0x42(%rcx), %xmm5, %xmm6

	vcmpnlt_uqss	%xmm0, %xmm1, %xmm2
	vcmpnlt_uqss	(%rax), %xmm3, %xmm4
	vcmpnlt_uqss	0x42(%rcx), %xmm5, %xmm6

	vcmpnltpd	%xmm0, %xmm1, %xmm2
	vcmpnltpd	(%rax), %xmm3, %xmm4
	vcmpnltpd	0x42(%rcx), %xmm5, %xmm6
	vcmpnltpd	%ymm0, %ymm1, %ymm2
	vcmpnltpd	(%rbx), %ymm3, %ymm4
	vcmpnltpd	0x42(%rdx), %ymm5, %ymm6

	vcmpnltps	%xmm0, %xmm1, %xmm2
	vcmpnltps	(%rax), %xmm3, %xmm4
	vcmpnltps	0x42(%rcx), %xmm5, %xmm6
	vcmpnltps	%ymm0, %ymm1, %ymm2
	vcmpnltps	(%rbx), %ymm3, %ymm4
	vcmpnltps	0x42(%rdx), %ymm5, %ymm6

	vcmpnltsd	%xmm0, %xmm1, %xmm2
	vcmpnltsd	(%rax), %xmm3, %xmm4
	vcmpnltsd	0x42(%rcx), %xmm5, %xmm6

	vcmpnltss	%xmm0, %xmm1, %xmm2
	vcmpnltss	(%rax), %xmm3, %xmm4
	vcmpnltss	0x42(%rcx), %xmm5, %xmm6

	vcmpord_spd	%xmm0, %xmm1, %xmm2
	vcmpord_spd	(%rax), %xmm3, %xmm4
	vcmpord_spd	0x42(%rcx), %xmm5, %xmm6
	vcmpord_spd	%ymm0, %ymm1, %ymm2
	vcmpord_spd	(%rbx), %ymm3, %ymm4
	vcmpord_spd	0x42(%rdx), %ymm5, %ymm6

	vcmpord_sps	%xmm0, %xmm1, %xmm2
	vcmpord_sps	(%rax), %xmm3, %xmm4
	vcmpord_sps	0x42(%rcx), %xmm5, %xmm6
	vcmpord_sps	%ymm0, %ymm1, %ymm2
	vcmpord_sps	(%rbx), %ymm3, %ymm4
	vcmpord_sps	0x42(%rdx), %ymm5, %ymm6

	vcmpord_ssd	%xmm0, %xmm1, %xmm2
	vcmpord_ssd	(%rax), %xmm3, %xmm4
	vcmpord_ssd	0x42(%rcx), %xmm5, %xmm6

	vcmpord_sss	%xmm0, %xmm1, %xmm2
	vcmpord_sss	(%rax), %xmm3, %xmm4
	vcmpord_sss	0x42(%rcx), %xmm5, %xmm6

	vcmpordpd	%xmm0, %xmm1, %xmm2
	vcmpordpd	(%rax), %xmm3, %xmm4
	vcmpordpd	0x42(%rcx), %xmm5, %xmm6
	vcmpordpd	%ymm0, %ymm1, %ymm2
	vcmpordpd	(%rbx), %ymm3, %ymm4
	vcmpordpd	0x42(%rdx), %ymm5, %ymm6

	vcmpordps	%xmm0, %xmm1, %xmm2
	vcmpordps	(%rax), %xmm3, %xmm4
	vcmpordps	0x42(%rcx), %xmm5, %xmm6
	vcmpordps	%ymm0, %ymm1, %ymm2
	vcmpordps	(%rbx), %ymm3, %ymm4
	vcmpordps	0x42(%rdx), %ymm5, %ymm6

	vcmpordsd	%xmm0, %xmm1, %xmm2
	vcmpordsd	(%rax), %xmm3, %xmm4
	vcmpordsd	0x42(%rcx), %xmm5, %xmm6

	vcmpordss	%xmm0, %xmm1, %xmm2
	vcmpordss	(%rax), %xmm3, %xmm4
	vcmpordss	0x42(%rcx), %xmm5, %xmm6

	vcmppd	$0x48, %xmm3, %xmm5, %xmm7
	vcmppd	$0x48, (%rbx), %xmm2, %xmm4
	vcmppd	$0x48, 0x8(%rbx), %xmm1, %xmm6
	vcmppd	$0x48, %ymm3, %ymm5, %ymm7
	vcmppd	$0x48, (%rbx), %ymm2, %ymm4
	vcmppd	$0x48, 0x8(%rbx), %ymm1, %ymm6

	vcmpps	$0x48, %xmm3, %xmm5, %xmm7
	vcmpps	$0x48, (%rbx), %xmm2, %xmm4
	vcmpps	$0x48, 0x8(%rbx), %xmm1, %xmm6
	vcmpps	$0x48, %ymm3, %ymm5, %ymm7
	vcmpps	$0x48, (%rbx), %ymm2, %ymm4
	vcmpps	$0x48, 0x8(%rbx), %ymm1, %ymm6

	vcmpsd	$0x48, %xmm3, %xmm5, %xmm7
	vcmpsd	$0x48, (%rbx), %xmm2, %xmm4
	vcmpsd	$0x48, 0x8(%rbx), %xmm1, %xmm6

	vcmpss	$0x48, %xmm3, %xmm5, %xmm7
	vcmpss	$0x48, (%rbx), %xmm2, %xmm4
	vcmpss	$0x48, 0x8(%rbx), %xmm1, %xmm6

	vcmptrue_uspd	%xmm0, %xmm1, %xmm2
	vcmptrue_uspd	(%rax), %xmm3, %xmm4
	vcmptrue_uspd	0x42(%rcx), %xmm5, %xmm6
	vcmptrue_uspd	%ymm0, %ymm1, %ymm2
	vcmptrue_uspd	(%rbx), %ymm3, %ymm4
	vcmptrue_uspd	0x42(%rdx), %ymm5, %ymm6

	vcmptrue_usps	%xmm0, %xmm1, %xmm2
	vcmptrue_usps	(%rax), %xmm3, %xmm4
	vcmptrue_usps	0x42(%rcx), %xmm5, %xmm6
	vcmptrue_usps	%ymm0, %ymm1, %ymm2
	vcmptrue_usps	(%rbx), %ymm3, %ymm4
	vcmptrue_usps	0x42(%rdx), %ymm5, %ymm6

	vcmptrue_ussd	%xmm0, %xmm1, %xmm2
	vcmptrue_ussd	(%rax), %xmm3, %xmm4
	vcmptrue_ussd	0x42(%rcx), %xmm5, %xmm6

	vcmptrue_usss	%xmm0, %xmm1, %xmm2
	vcmptrue_usss	(%rax), %xmm3, %xmm4
	vcmptrue_usss	0x42(%rcx), %xmm5, %xmm6

	vcmptruepd	%xmm0, %xmm1, %xmm2
	vcmptruepd	(%rax), %xmm3, %xmm4
	vcmptruepd	0x42(%rcx), %xmm5, %xmm6
	vcmptruepd	%ymm0, %ymm1, %ymm2
	vcmptruepd	(%rbx), %ymm3, %ymm4
	vcmptruepd	0x42(%rdx), %ymm5, %ymm6

	vcmptrueps	%xmm0, %xmm1, %xmm2
	vcmptrueps	(%rax), %xmm3, %xmm4
	vcmptrueps	0x42(%rcx), %xmm5, %xmm6
	vcmptrueps	%ymm0, %ymm1, %ymm2
	vcmptrueps	(%rbx), %ymm3, %ymm4
	vcmptrueps	0x42(%rdx), %ymm5, %ymm6

	vcmptruesd	%xmm0, %xmm1, %xmm2
	vcmptruesd	(%rax), %xmm3, %xmm4
	vcmptruesd	0x42(%rcx), %xmm5, %xmm6

	vcmptruess	%xmm0, %xmm1, %xmm2
	vcmptruess	(%rax), %xmm3, %xmm4
	vcmptruess	0x42(%rcx), %xmm5, %xmm6

	vcmpunord_spd	%xmm0, %xmm1, %xmm2
	vcmpunord_spd	(%rax), %xmm3, %xmm4
	vcmpunord_spd	0x42(%rcx), %xmm5, %xmm6
	vcmpunord_spd	%ymm0, %ymm1, %ymm2
	vcmpunord_spd	(%rbx), %ymm3, %ymm4
	vcmpunord_spd	0x42(%rdx), %ymm5, %ymm6

	vcmpunord_sps	%xmm0, %xmm1, %xmm2
	vcmpunord_sps	(%rax), %xmm3, %xmm4
	vcmpunord_sps	0x42(%rcx), %xmm5, %xmm6
	vcmpunord_sps	%ymm0, %ymm1, %ymm2
	vcmpunord_sps	(%rbx), %ymm3, %ymm4
	vcmpunord_sps	0x42(%rdx), %ymm5, %ymm6

	vcmpunord_ssd	%xmm0, %xmm1, %xmm2
	vcmpunord_ssd	(%rax), %xmm3, %xmm4
	vcmpunord_ssd	0x42(%rcx), %xmm5, %xmm6

	vcmpunord_sss	%xmm0, %xmm1, %xmm2
	vcmpunord_sss	(%rax), %xmm3, %xmm4
	vcmpunord_sss	0x42(%rcx), %xmm5, %xmm6

	vcmpunordpd	%xmm0, %xmm1, %xmm2
	vcmpunordpd	(%rax), %xmm3, %xmm4
	vcmpunordpd	0x42(%rcx), %xmm5, %xmm6
	vcmpunordpd	%ymm0, %ymm1, %ymm2
	vcmpunordpd	(%rbx), %ymm3, %ymm4
	vcmpunordpd	0x42(%rdx), %ymm5, %ymm6

	vcmpunordps	%xmm0, %xmm1, %xmm2
	vcmpunordps	(%rax), %xmm3, %xmm4
	vcmpunordps	0x42(%rcx), %xmm5, %xmm6
	vcmpunordps	%ymm0, %ymm1, %ymm2
	vcmpunordps	(%rbx), %ymm3, %ymm4
	vcmpunordps	0x42(%rdx), %ymm5, %ymm6

	vcmpunordsd	%xmm0, %xmm1, %xmm2
	vcmpunordsd	(%rax), %xmm3, %xmm4
	vcmpunordsd	0x42(%rcx), %xmm5, %xmm6

	vcmpunordss	%xmm0, %xmm1, %xmm2
	vcmpunordss	(%rax), %xmm3, %xmm4
	vcmpunordss	0x42(%rcx), %xmm5, %xmm6

	vcomisd	%xmm0, %xmm1
	vcomisd	(%rsi), %xmm3
	vcomisd	0x42(%rdi), %xmm3

	vcomiss	%xmm0, %xmm1
	vcomiss	(%rsi), %xmm3
	vcomiss	0x42(%rdi), %xmm3

	vcvtdq2pd	%xmm0, %xmm1
	vcvtdq2pd	(%rsi), %xmm3
	vcvtdq2pd	0x42(%rdi), %xmm3
	vcvtdq2pd	%xmm7, %ymm6
	vcvtdq2pd	(%rbp), %ymm4
	vcvtdq2pd	0x42(%rsp), %ymm4

	vcvtdq2ps	%xmm0, %xmm1
	vcvtdq2ps	(%rsi), %xmm3
	vcvtdq2ps	0x42(%rdi), %xmm3
	vcvtdq2ps	%ymm7, %ymm6
	vcvtdq2ps	(%rbp), %ymm4
	vcvtdq2ps	0x42(%rsp), %ymm4

	vcvtpd2dq	%ymm6, %xmm3

	vcvtpd2dqx	%xmm0, %xmm1
	vcvtpd2dqx	(%rsi), %xmm3
	vcvtpd2dqx	0x42(%rdi), %xmm3

	vcvtpd2dqy	%ymm7, %xmm6
	vcvtpd2dqy	(%rbp), %xmm4
	vcvtpd2dqy	0x42(%rsp), %xmm4

	vcvtpd2ps	%ymm6, %xmm3

	vcvtpd2psx	%xmm0, %xmm1
	vcvtpd2psx	(%rsi), %xmm3
	vcvtpd2psx	0x42(%rdi), %xmm3

	vcvtpd2psy	%ymm7, %xmm6
	vcvtpd2psy	(%rbp), %xmm4
	vcvtpd2psy	0x42(%rsp), %xmm4

	vcvtps2dq	%xmm0, %xmm1
	vcvtps2dq	(%rsi), %xmm3
	vcvtps2dq	0x42(%rdi), %xmm3
	vcvtps2dq	%ymm7, %ymm6
	vcvtps2dq	(%rbp), %ymm4
	vcvtps2dq	0x42(%rsp), %ymm4

	vcvtps2pd	%xmm0, %xmm1
	vcvtps2pd	(%rsi), %xmm3
	vcvtps2pd	0x42(%rdi), %xmm3
	vcvtps2pd	%xmm7, %ymm6
	vcvtps2pd	(%rbp), %ymm4
	vcvtps2pd	0x42(%rsp), %ymm4

	vcvtsd2si	%xmm6, %rax
	vcvtsd2si	(%rbx), %rax
	vcvtsd2si	0x24(%rbx), %rax

	vcvtsd2ss	%xmm0, %xmm1, %xmm2
	vcvtsd2ss	(%rax), %xmm3, %xmm4
	vcvtsd2ss	0x42(%rcx), %xmm5, %xmm6

	vcvtss2sd	%xmm0, %xmm1, %xmm2
	vcvtss2sd	(%rax), %xmm3, %xmm4
	vcvtss2sd	0x42(%rcx), %xmm5, %xmm6

	vcvtss2si	%xmm6, %rax
	vcvtss2si	(%rbx), %rax
	vcvtss2si	0x24(%rbx), %rax

	vcvttpd2dq	%xmm0, %xmm5

	vcvttpd2dqx	%xmm0, %xmm1
	vcvttpd2dqx	(%rsi), %xmm3
	vcvttpd2dqx	0x42(%rdi), %xmm3

	vcvttpd2dqy	%ymm7, %xmm6
	vcvttpd2dqy	(%rbp), %xmm4
	vcvttpd2dqy	0x42(%rsp), %xmm4

	vcvttps2dq	%xmm0, %xmm1
	vcvttps2dq	(%rsi), %xmm3
	vcvttps2dq	0x42(%rdi), %xmm3
	vcvttps2dq	%ymm7, %ymm6
	vcvttps2dq	(%rbp), %ymm4
	vcvttps2dq	0x42(%rsp), %ymm4

	vcvttsd2si	%xmm6, %rax
	vcvttsd2si	(%rbx), %rax
	vcvttsd2si	0x24(%rbx), %rax

	vcvttss2si	%xmm6, %rax
	vcvttss2si	(%rbx), %rax
	vcvttss2si	0x24(%rbx), %rax

	vdivpd	%xmm0, %xmm1, %xmm2
	vdivpd	(%rax), %xmm3, %xmm4
	vdivpd	0x42(%rcx), %xmm5, %xmm6
	vdivpd	%ymm0, %ymm1, %ymm2
	vdivpd	(%rbx), %ymm3, %ymm4
	vdivpd	0x42(%rdx), %ymm5, %ymm6

	vdivps	%xmm0, %xmm1, %xmm2
	vdivps	(%rax), %xmm3, %xmm4
	vdivps	0x42(%rcx), %xmm5, %xmm6
	vdivps	%ymm0, %ymm1, %ymm2
	vdivps	(%rbx), %ymm3, %ymm4
	vdivps	0x42(%rdx), %ymm5, %ymm6

	vdivsd	%xmm0, %xmm1, %xmm2
	vdivsd	(%rax), %xmm3, %xmm4
	vdivsd	0x42(%rcx), %xmm5, %xmm6

	vdivss	%xmm0, %xmm1, %xmm2
	vdivss	(%rax), %xmm3, %xmm4
	vdivss	0x42(%rcx), %xmm5, %xmm6

	vdppd	$0x48, %xmm3, %xmm5, %xmm7
	vdppd	$0x48, (%rbx), %xmm2, %xmm4
	vdppd	$0x48, 0x8(%rbx), %xmm1, %xmm6

	vdpps	$0x48, %xmm3, %xmm5, %xmm7
	vdpps	$0x48, (%rbx), %xmm2, %xmm4
	vdpps	$0x48, 0x8(%rbx), %xmm1, %xmm6
	vdpps	$0x48, %ymm3, %ymm5, %ymm7
	vdpps	$0x48, (%rbx), %ymm2, %ymm4
	vdpps	$0x48, 0x8(%rbx), %ymm1, %ymm6

	vextractf128	$0x30, %ymm0, %xmm1
	vextractf128	$0x30, %ymm0, (%rcx)
	vextractf128	$0x30, %ymm0, 0x24(%rdx)

	vextractps	$0x30, %xmm0, %rax
	vextractps	$0x30, %xmm0, (%rcx)
	vextractps	$0x30, %xmm0, 0x24(%rdx)

	vhaddpd	%xmm0, %xmm1, %xmm2
	vhaddpd	(%rax), %xmm3, %xmm4
	vhaddpd	0x42(%rcx), %xmm5, %xmm6
	vhaddpd	%ymm0, %ymm1, %ymm2
	vhaddpd	(%rbx), %ymm3, %ymm4
	vhaddpd	0x42(%rdx), %ymm5, %ymm6

	vhaddps	%xmm0, %xmm1, %xmm2
	vhaddps	(%rax), %xmm3, %xmm4
	vhaddps	0x42(%rcx), %xmm5, %xmm6
	vhaddps	%ymm0, %ymm1, %ymm2
	vhaddps	(%rbx), %ymm3, %ymm4
	vhaddps	0x42(%rdx), %ymm5, %ymm6

	vhsubpd	%xmm0, %xmm1, %xmm2
	vhsubpd	(%rax), %xmm3, %xmm4
	vhsubpd	0x42(%rcx), %xmm5, %xmm6
	vhsubpd	%ymm0, %ymm1, %ymm2
	vhsubpd	(%rbx), %ymm3, %ymm4
	vhsubpd	0x42(%rdx), %ymm5, %ymm6

	vhsubps	%xmm0, %xmm1, %xmm2
	vhsubps	(%rax), %xmm3, %xmm4
	vhsubps	0x42(%rcx), %xmm5, %xmm6
	vhsubps	%ymm0, %ymm1, %ymm2
	vhsubps	(%rbx), %ymm3, %ymm4
	vhsubps	0x42(%rdx), %ymm5, %ymm6

	vinsertf128	$0x48, %xmm3, %ymm5, %ymm7
	vinsertf128	$0x48, (%rbx), %ymm2, %ymm4
	vinsertf128	$0x48, 0x8(%rbx), %ymm1, %ymm6

	vinsertps	$0x48, %xmm3, %xmm5, %xmm7
	vinsertps	$0x48, (%rbx), %xmm2, %xmm4
	vinsertps	$0x48, 0x8(%rbx), %xmm1, %xmm6

	vlddqu	(%rbx), %xmm2
	vlddqu	0x8(%rbx), %xmm1
	vlddqu	(%rbx), %ymm2
	vlddqu	0x8(%rbx), %ymm1

	vldmxcsr	(%rdx)
	vldmxcsr	0x8(%rdx)

	vmaskmovdqu	%xmm0, %xmm5

	vmaskmovpd	(%rbx), %xmm4, %xmm2
	vmaskmovpd	0x8(%rbx), %xmm2, %xmm1

	vmaskmovps	(%rbx), %ymm4, %ymm2
	vmaskmovps	0x8(%rbx), %ymm3, %ymm1

	vmaxpd	%xmm0, %xmm1, %xmm2
	vmaxpd	(%rax), %xmm3, %xmm4
	vmaxpd	0x42(%rcx), %xmm5, %xmm6
	vmaxpd	%ymm0, %ymm1, %ymm2
	vmaxpd	(%rbx), %ymm3, %ymm4
	vmaxpd	0x42(%rdx), %ymm5, %ymm6

	vmaxps	%xmm0, %xmm1, %xmm2
	vmaxps	(%rax), %xmm3, %xmm4
	vmaxps	0x42(%rcx), %xmm5, %xmm6
	vmaxps	%ymm0, %ymm1, %ymm2
	vmaxps	(%rbx), %ymm3, %ymm4
	vmaxps	0x42(%rdx), %ymm5, %ymm6

	vmaxsd	%xmm0, %xmm1, %xmm2
	vmaxsd	(%rax), %xmm3, %xmm4
	vmaxsd	0x42(%rcx), %xmm5, %xmm6

	vmaxss	%xmm0, %xmm1, %xmm2
	vmaxss	(%rax), %xmm3, %xmm4
	vmaxss	0x42(%rcx), %xmm5, %xmm6

	vminpd	%xmm0, %xmm1, %xmm2
	vminpd	(%rax), %xmm3, %xmm4
	vminpd	0x42(%rcx), %xmm5, %xmm6
	vminpd	%ymm0, %ymm1, %ymm2
	vminpd	(%rbx), %ymm3, %ymm4
	vminpd	0x42(%rdx), %ymm5, %ymm6

	vminps	%xmm0, %xmm1, %xmm2
	vminps	(%rax), %xmm3, %xmm4
	vminps	0x42(%rcx), %xmm5, %xmm6
	vminps	%ymm0, %ymm1, %ymm2
	vminps	(%rbx), %ymm3, %ymm4
	vminps	0x42(%rdx), %ymm5, %ymm6

	vminsd	%xmm0, %xmm1, %xmm2
	vminsd	(%rax), %xmm3, %xmm4
	vminsd	0x42(%rcx), %xmm5, %xmm6

	vminss	%xmm0, %xmm1, %xmm2
	vminss	(%rax), %xmm3, %xmm4
	vminss	0x42(%rcx), %xmm5, %xmm6

	vmovapd	%xmm0, %xmm1
	vmovapd	(%rsi), %xmm3
	vmovapd	0x42(%rdi), %xmm3
	vmovapd	%ymm7, %ymm6
	vmovapd	(%rbp), %ymm4
	vmovapd	0x42(%rsp), %ymm4
	vmovapd	%xmm1, %xmm0
	vmovapd	%xmm3, (%rsi)
	vmovapd	%xmm3, 0x42(%rdi)
	vmovapd	%ymm1, %ymm0
	vmovapd	%ymm3, (%rsi)
	vmovapd	%ymm3, 0x42(%rdi)

	vmovaps	%xmm0, %xmm1
	vmovaps	(%rsi), %xmm3
	vmovaps	0x42(%rdi), %xmm3
	vmovaps	%ymm7, %ymm6
	vmovaps	(%rbp), %ymm4
	vmovaps	0x42(%rsp), %ymm4
	vmovaps	%xmm1, %xmm0
	vmovaps	%xmm3, (%rsi)
	vmovaps	%xmm3, 0x42(%rdi)
	vmovaps	%ymm1, %ymm0
	vmovaps	%ymm3, (%rsi)
	vmovaps	%ymm3, 0x42(%rdi)

	vmovd	%rax, %xmm0
	vmovd	(%rax), %xmm1
	vmovd	0x14(%rax), %xmm1

	vmovddup	%xmm0, %xmm1
	vmovddup	(%rsi), %xmm3
	vmovddup	0x42(%rdi), %xmm3
	vmovddup	%ymm7, %ymm6
	vmovddup	(%rbp), %ymm4
	vmovddup	0x42(%rsp), %ymm4

	vmovdqa	%xmm0, %xmm1
	vmovdqa	(%rsi), %xmm3
	vmovdqa	0x42(%rdi), %xmm3
	vmovdqa	%ymm7, %ymm6
	vmovdqa	(%rbp), %ymm4
	vmovdqa	0x42(%rsp), %ymm4
	vmovdqa	%xmm1, %xmm0
	vmovdqa	%xmm3, (%rsi)
	vmovdqa	%xmm3, 0x42(%rdi)
	vmovdqa	%ymm1, %ymm0
	vmovdqa	%ymm3, (%rsi)
	vmovdqa	%ymm3, 0x42(%rdi)

	vmovdqu	%xmm0, %xmm1
	vmovdqu	(%rsi), %xmm3
	vmovdqu	0x42(%rdi), %xmm3
	vmovdqu	%ymm7, %ymm6
	vmovdqu	(%rbp), %ymm4
	vmovdqu	0x42(%rsp), %ymm4
	vmovdqu	%xmm1, %xmm0
	vmovdqu	%xmm3, (%rsi)
	vmovdqu	%xmm3, 0x42(%rdi)
	vmovdqu	%ymm1, %ymm0
	vmovdqu	%ymm3, (%rsi)
	vmovdqu	%ymm3, 0x42(%rdi)

	vmovhlps	%xmm0, %xmm2, %xmm4

	vmovhpd	(%rbx), %xmm4, %xmm2
	vmovhpd	0x8(%rbx), %xmm3, %xmm1
	vmovhpd	%xmm3, (%rsi)
	vmovhpd	%xmm3, 0x42(%rdi)

	vmovhps	(%rbx), %xmm4, %xmm2
	vmovhps	0x8(%rbx), %xmm3, %xmm1
	vmovhps	%xmm3, (%rsi)
	vmovhps	%xmm3, 0x42(%rdi)

	vmovlhps	%xmm1, %xmm3, %xmm5

	vmovlpd	(%rbx), %xmm4, %xmm2
	vmovlpd	0x8(%rbx), %xmm3, %xmm1
	vmovlpd	%xmm3, (%rsi)
	vmovlpd	%xmm3, 0x42(%rdi)

	vmovlps	(%rbx), %xmm4, %xmm2
	vmovlps	0x8(%rbx), %xmm3, %xmm1
	vmovlps	%xmm3, (%rsi)
	vmovlps	%xmm3, 0x42(%rdi)

	vmovmskpd	%xmm0, %rax
	vmovmskpd	%ymm1, %rbx

	vmovmskps	%xmm2, %rcx
	vmovmskps	%ymm3, %rdx

	vmovntdq	%xmm5, (%rdi)
	vmovntdq	%xmm5, 0x24(%rdi)
	vmovntdq	%ymm6, (%rsi)
	vmovntdq	%ymm6, 0x24(%rsi)

	vmovntdqa	(%rbx), %xmm2
	vmovntdqa	0x8(%rbx), %xmm1
	vmovntdqa	(%rbx), %ymm2
	vmovntdqa	0x8(%rbx), %ymm1

	vmovntpd	%xmm3, (%rsi)
	vmovntpd	%xmm3, 0x42(%rdi)
	vmovntpd	%ymm3, (%rsi)
	vmovntpd	%ymm3, 0x42(%rdi)

	vmovntps	%xmm3, (%rsi)
	vmovntps	%xmm3, 0x42(%rdi)
	vmovntps	%ymm3, (%rsi)
	vmovntps	%ymm3, 0x42(%rdi)

	vmovq	%xmm0, %rax
	vmovq	%xmm0, (%rax)
	vmovq	%xmm0, 0x10(%rax)
	vmovq	0x10(%rbx), %xmm1
	vmovq	(%rbx), %xmm1
	vmovq	%rbx, %xmm1

	vmovsd	%xmm0, %xmm2, %xmm4
	vmovsd	(%rax), %xmm1
	vmovsd	0x32(%rax), %xmm2

	vmovshdup	%xmm0, %xmm2
	vmovshdup	(%rax), %xmm1
	vmovshdup	0x10(%rax), %xmm1
	vmovshdup	%ymm0, %ymm2
	vmovshdup	(%rbx), %ymm1
	vmovshdup	0x10(%rbx), %ymm3

	vmovsldup	%xmm0, %xmm2
	vmovsldup	(%rax), %xmm1
	vmovsldup	0x10(%rax), %xmm1
	vmovsldup	%ymm0, %ymm2
	vmovsldup	(%rbx), %ymm1
	vmovsldup	0x10(%rbx), %ymm3

	vmovss	%xmm0, %xmm2, %xmm4
	vmovss	(%rax), %xmm1
	vmovss	0x32(%rax), %xmm2

	vmovupd	%xmm0, %xmm1
	vmovupd	(%rsi), %xmm3
	vmovupd	0x42(%rdi), %xmm3
	vmovupd	%ymm7, %ymm6
	vmovupd	(%rbp), %ymm4
	vmovupd	0x42(%rsp), %ymm4
	vmovupd	%xmm1, %xmm0
	vmovupd	%xmm3, (%rsi)
	vmovupd	%xmm3, 0x42(%rdi)
	vmovupd	%ymm1, %ymm0
	vmovupd	%ymm3, (%rsi)
	vmovupd	%ymm3, 0x42(%rdi)

	vmovups	%xmm0, %xmm1
	vmovups	(%rsi), %xmm3
	vmovups	0x42(%rdi), %xmm3
	vmovups	%ymm7, %ymm6
	vmovups	(%rbp), %ymm4
	vmovups	0x42(%rsp), %ymm4
	vmovups	%xmm1, %xmm0
	vmovups	%xmm3, (%rsi)
	vmovups	%xmm3, 0x42(%rdi)
	vmovups	%ymm1, %ymm0
	vmovups	%ymm3, (%rsi)
	vmovups	%ymm3, 0x42(%rdi)

	vmpsadbw	$0x48, %xmm3, %xmm5, %xmm7
	vmpsadbw	$0x48, (%rbx), %xmm2, %xmm4
	vmpsadbw	$0x48, 0x8(%rbx), %xmm1, %xmm6
	vmpsadbw	$0x48, %ymm3, %ymm5, %ymm7
	vmpsadbw	$0x48, (%rbx), %ymm2, %ymm4
	vmpsadbw	$0x48, 0x8(%rbx), %ymm1, %ymm6

	vmulpd	%xmm0, %xmm1, %xmm2
	vmulpd	(%rax), %xmm3, %xmm4
	vmulpd	0x42(%rcx), %xmm5, %xmm6
	vmulpd	%ymm0, %ymm1, %ymm2
	vmulpd	(%rbx), %ymm3, %ymm4
	vmulpd	0x42(%rdx), %ymm5, %ymm6

	vmulps	%xmm0, %xmm1, %xmm2
	vmulps	(%rax), %xmm3, %xmm4
	vmulps	0x42(%rcx), %xmm5, %xmm6
	vmulps	%ymm0, %ymm1, %ymm2
	vmulps	(%rbx), %ymm3, %ymm4
	vmulps	0x42(%rdx), %ymm5, %ymm6

	vmulsd	%xmm0, %xmm1, %xmm2
	vmulsd	(%rax), %xmm3, %xmm4
	vmulsd	0x42(%rcx), %xmm5, %xmm6

	vmulss	%xmm0, %xmm1, %xmm2
	vmulss	(%rax), %xmm3, %xmm4
	vmulss	0x42(%rcx), %xmm5, %xmm6

	vorpd	%xmm0, %xmm1, %xmm2
	vorpd	(%rax), %xmm3, %xmm4
	vorpd	0x42(%rcx), %xmm5, %xmm6
	vorpd	%ymm0, %ymm1, %ymm2
	vorpd	(%rbx), %ymm3, %ymm4
	vorpd	0x42(%rdx), %ymm5, %ymm6

	vorps	%xmm0, %xmm1, %xmm2
	vorps	(%rax), %xmm3, %xmm4
	vorps	0x42(%rcx), %xmm5, %xmm6
	vorps	%ymm0, %ymm1, %ymm2
	vorps	(%rbx), %ymm3, %ymm4
	vorps	0x42(%rdx), %ymm5, %ymm6

	vpabsb	%xmm0, %xmm1
	vpabsb	(%rsi), %xmm3
	vpabsb	0x42(%rdi), %xmm3
	vpabsb	%ymm7, %ymm6
	vpabsb	(%rbp), %ymm4
	vpabsb	0x42(%rsp), %ymm4

	vpabsd	%xmm0, %xmm1
	vpabsd	(%rsi), %xmm3
	vpabsd	0x42(%rdi), %xmm3
	vpabsd	%ymm7, %ymm6
	vpabsd	(%rbp), %ymm4
	vpabsd	0x42(%rsp), %ymm4

	vpabsw	%xmm0, %xmm1
	vpabsw	(%rsi), %xmm3
	vpabsw	0x42(%rdi), %xmm3
	vpabsw	%ymm7, %ymm6
	vpabsw	(%rbp), %ymm4
	vpabsw	0x42(%rsp), %ymm4

	vpackssdw	%xmm0, %xmm1, %xmm2
	vpackssdw	(%rax), %xmm3, %xmm4
	vpackssdw	0x42(%rcx), %xmm5, %xmm6
	vpackssdw	%ymm0, %ymm1, %ymm2
	vpackssdw	(%rbx), %ymm3, %ymm4
	vpackssdw	0x42(%rdx), %ymm5, %ymm6

	vpacksswb	%xmm0, %xmm1, %xmm2
	vpacksswb	(%rax), %xmm3, %xmm4
	vpacksswb	0x42(%rcx), %xmm5, %xmm6
	vpacksswb	%ymm0, %ymm1, %ymm2
	vpacksswb	(%rbx), %ymm3, %ymm4
	vpacksswb	0x42(%rdx), %ymm5, %ymm6

	vpackusdw	%xmm0, %xmm1, %xmm2
	vpackusdw	(%rax), %xmm3, %xmm4
	vpackusdw	0x42(%rcx), %xmm5, %xmm6
	vpackusdw	%ymm0, %ymm1, %ymm2
	vpackusdw	(%rbx), %ymm3, %ymm4
	vpackusdw	0x42(%rdx), %ymm5, %ymm6

	vpackuswb	%xmm0, %xmm1, %xmm2
	vpackuswb	(%rax), %xmm3, %xmm4
	vpackuswb	0x42(%rcx), %xmm5, %xmm6
	vpackuswb	%ymm0, %ymm1, %ymm2
	vpackuswb	(%rbx), %ymm3, %ymm4
	vpackuswb	0x42(%rdx), %ymm5, %ymm6

	vpaddb	%xmm0, %xmm1, %xmm2
	vpaddb	(%rax), %xmm3, %xmm4
	vpaddb	0x42(%rcx), %xmm5, %xmm6
	vpaddb	%ymm0, %ymm1, %ymm2
	vpaddb	(%rbx), %ymm3, %ymm4
	vpaddb	0x42(%rdx), %ymm5, %ymm6

	vpaddd	%xmm0, %xmm1, %xmm2
	vpaddd	(%rax), %xmm3, %xmm4
	vpaddd	0x42(%rcx), %xmm5, %xmm6
	vpaddd	%ymm0, %ymm1, %ymm2
	vpaddd	(%rbx), %ymm3, %ymm4
	vpaddd	0x42(%rdx), %ymm5, %ymm6

	vpaddq	%xmm0, %xmm1, %xmm2
	vpaddq	(%rax), %xmm3, %xmm4
	vpaddq	0x42(%rcx), %xmm5, %xmm6
	vpaddq	%ymm0, %ymm1, %ymm2
	vpaddq	(%rbx), %ymm3, %ymm4
	vpaddq	0x42(%rdx), %ymm5, %ymm6

	vpaddsb	%xmm0, %xmm1, %xmm2
	vpaddsb	(%rax), %xmm3, %xmm4
	vpaddsb	0x42(%rcx), %xmm5, %xmm6
	vpaddsb	%ymm0, %ymm1, %ymm2
	vpaddsb	(%rbx), %ymm3, %ymm4
	vpaddsb	0x42(%rdx), %ymm5, %ymm6

	vpaddsw	%xmm0, %xmm1, %xmm2
	vpaddsw	(%rax), %xmm3, %xmm4
	vpaddsw	0x42(%rcx), %xmm5, %xmm6
	vpaddsw	%ymm0, %ymm1, %ymm2
	vpaddsw	(%rbx), %ymm3, %ymm4
	vpaddsw	0x42(%rdx), %ymm5, %ymm6

	vpaddusb	%xmm0, %xmm1, %xmm2
	vpaddusb	(%rax), %xmm3, %xmm4
	vpaddusb	0x42(%rcx), %xmm5, %xmm6
	vpaddusb	%ymm0, %ymm1, %ymm2
	vpaddusb	(%rbx), %ymm3, %ymm4
	vpaddusb	0x42(%rdx), %ymm5, %ymm6

	vpaddusw	%xmm0, %xmm1, %xmm2
	vpaddusw	(%rax), %xmm3, %xmm4
	vpaddusw	0x42(%rcx), %xmm5, %xmm6
	vpaddusw	%ymm0, %ymm1, %ymm2
	vpaddusw	(%rbx), %ymm3, %ymm4
	vpaddusw	0x42(%rdx), %ymm5, %ymm6

	vpaddw	%xmm0, %xmm1, %xmm2
	vpaddw	(%rax), %xmm3, %xmm4
	vpaddw	0x42(%rcx), %xmm5, %xmm6
	vpaddw	%ymm0, %ymm1, %ymm2
	vpaddw	(%rbx), %ymm3, %ymm4
	vpaddw	0x42(%rdx), %ymm5, %ymm6

	vpalignr	$0x48, %xmm3, %xmm5, %xmm7
	vpalignr	$0x48, (%rbx), %xmm2, %xmm4
	vpalignr	$0x48, 0x8(%rbx), %xmm1, %xmm6
	vpalignr	$0x48, %ymm3, %ymm5, %ymm7
	vpalignr	$0x48, (%rbx), %ymm2, %ymm4
	vpalignr	$0x48, 0x8(%rbx), %ymm1, %ymm6

	vpand	%xmm0, %xmm1, %xmm2
	vpand	(%rax), %xmm3, %xmm4
	vpand	0x42(%rcx), %xmm5, %xmm6
	vpand	%ymm0, %ymm1, %ymm2
	vpand	(%rbx), %ymm3, %ymm4
	vpand	0x42(%rdx), %ymm5, %ymm6

	vpandn	%xmm0, %xmm1, %xmm2
	vpandn	(%rax), %xmm3, %xmm4
	vpandn	0x42(%rcx), %xmm5, %xmm6
	vpandn	%ymm0, %ymm1, %ymm2
	vpandn	(%rbx), %ymm3, %ymm4
	vpandn	0x42(%rdx), %ymm5, %ymm6

	vpavgb	%xmm0, %xmm1, %xmm2
	vpavgb	(%rax), %xmm3, %xmm4
	vpavgb	0x42(%rcx), %xmm5, %xmm6
	vpavgb	%ymm0, %ymm1, %ymm2
	vpavgb	(%rbx), %ymm3, %ymm4
	vpavgb	0x42(%rdx), %ymm5, %ymm6

	vpavgw	%xmm0, %xmm1, %xmm2
	vpavgw	(%rax), %xmm3, %xmm4
	vpavgw	0x42(%rcx), %xmm5, %xmm6
	vpavgw	%ymm0, %ymm1, %ymm2
	vpavgw	(%rbx), %ymm3, %ymm4
	vpavgw	0x42(%rdx), %ymm5, %ymm6

	vpblendvb	%xmm0, %xmm1, %xmm2, %xmm3
	vpblendvb	%xmm0, (%rax), %xmm2, %xmm3
	vpblendvb	%xmm0, 0x10(%rbx), %xmm2, %xmm3
	vpblendvb	%ymm0, %ymm1, %ymm2, %ymm3
	vpblendvb	%ymm0, (%rax), %ymm2, %ymm3
	vpblendvb	%ymm0, 0x10(%rbx), %ymm2, %ymm3

	vpblendw	$0x48, %xmm3, %xmm5, %xmm7
	vpblendw	$0x48, (%rbx), %xmm2, %xmm4
	vpblendw	$0x48, 0x8(%rbx), %xmm1, %xmm6
	vpblendw	$0x48, %ymm3, %ymm5, %ymm7
	vpblendw	$0x48, (%rbx), %ymm2, %ymm4
	vpblendw	$0x48, 0x8(%rbx), %ymm1, %ymm6

	vpclmulqdq	$0x48, %xmm3, %xmm5, %xmm7
	vpclmulqdq	$0x48, (%rbx), %xmm2, %xmm4
	vpclmulqdq	$0x48, 0x8(%rbx), %xmm1, %xmm6

	vpcmpeqb	%xmm0, %xmm1, %xmm2
	vpcmpeqb	(%rax), %xmm3, %xmm4
	vpcmpeqb	0x42(%rcx), %xmm5, %xmm6
	vpcmpeqb	%ymm0, %ymm1, %ymm2
	vpcmpeqb	(%rbx), %ymm3, %ymm4
	vpcmpeqb	0x42(%rdx), %ymm5, %ymm6

	vpcmpeqd	%xmm0, %xmm1, %xmm2
	vpcmpeqd	(%rax), %xmm3, %xmm4
	vpcmpeqd	0x42(%rcx), %xmm5, %xmm6
	vpcmpeqd	%ymm0, %ymm1, %ymm2
	vpcmpeqd	(%rbx), %ymm3, %ymm4
	vpcmpeqd	0x42(%rdx), %ymm5, %ymm6

	vpcmpeqq	%xmm0, %xmm1, %xmm2
	vpcmpeqq	(%rax), %xmm3, %xmm4
	vpcmpeqq	0x42(%rcx), %xmm5, %xmm6
	vpcmpeqq	%ymm0, %ymm1, %ymm2
	vpcmpeqq	(%rbx), %ymm3, %ymm4
	vpcmpeqq	0x42(%rdx), %ymm5, %ymm6

	vpcmpeqw	%xmm0, %xmm1, %xmm2
	vpcmpeqw	(%rax), %xmm3, %xmm4
	vpcmpeqw	0x42(%rcx), %xmm5, %xmm6
	vpcmpeqw	%ymm0, %ymm1, %ymm2
	vpcmpeqw	(%rbx), %ymm3, %ymm4
	vpcmpeqw	0x42(%rdx), %ymm5, %ymm6

	vpcmpestri	$0x42, %xmm0, %xmm1
	vpcmpestri	$0x23, 	(%rsi), %xmm3
	vpcmpestri	$0x42, 0x42(%rdi), %xmm3

	vpcmpestrm	$0x42, %xmm0, %xmm1
	vpcmpestrm	$0x23, 	(%rsi), %xmm3
	vpcmpestrm	$0x42, 0x42(%rdi), %xmm3

	vpcmpgtb	%xmm0, %xmm1, %xmm2
	vpcmpgtb	(%rax), %xmm3, %xmm4
	vpcmpgtb	0x42(%rcx), %xmm5, %xmm6
	vpcmpgtb	%ymm0, %ymm1, %ymm2
	vpcmpgtb	(%rbx), %ymm3, %ymm4
	vpcmpgtb	0x42(%rdx), %ymm5, %ymm6

	vpcmpgtd	%xmm0, %xmm1, %xmm2
	vpcmpgtd	(%rax), %xmm3, %xmm4
	vpcmpgtd	0x42(%rcx), %xmm5, %xmm6
	vpcmpgtd	%ymm0, %ymm1, %ymm2
	vpcmpgtd	(%rbx), %ymm3, %ymm4
	vpcmpgtd	0x42(%rdx), %ymm5, %ymm6

	vpcmpgtq	%xmm0, %xmm1, %xmm2
	vpcmpgtq	(%rax), %xmm3, %xmm4
	vpcmpgtq	0x42(%rcx), %xmm5, %xmm6
	vpcmpgtq	%ymm0, %ymm1, %ymm2
	vpcmpgtq	(%rbx), %ymm3, %ymm4
	vpcmpgtq	0x42(%rdx), %ymm5, %ymm6

	vpcmpgtw	%xmm0, %xmm1, %xmm2
	vpcmpgtw	(%rax), %xmm3, %xmm4
	vpcmpgtw	0x42(%rcx), %xmm5, %xmm6
	vpcmpgtw	%ymm0, %ymm1, %ymm2
	vpcmpgtw	(%rbx), %ymm3, %ymm4
	vpcmpgtw	0x42(%rdx), %ymm5, %ymm6

	vpcmpistri	$0x42, %xmm0, %xmm1
	vpcmpistri	$0x23, 	(%rsi), %xmm3
	vpcmpistri	$0x42, 0x42(%rdi), %xmm3

	vpcmpistrm	$0x42, %xmm0, %xmm1
	vpcmpistrm	$0x23, 	(%rsi), %xmm3
	vpcmpistrm	$0x42, 0x42(%rdi), %xmm3

	vperm2f128	$0x48, %ymm3, %ymm5, %ymm7
	vperm2f128	$0x48, (%rbx), %ymm2, %ymm4
	vperm2f128	$0x48, 0x8(%rbx), %ymm1, %ymm6

	vpermilpd	%xmm0, %xmm1, %xmm2
	vpermilpd	(%rax), %xmm3, %xmm4
	vpermilpd	0x42(%rcx), %xmm5, %xmm6
	vpermilpd	%ymm0, %ymm1, %ymm2
	vpermilpd	(%rbx), %ymm3, %ymm4
	vpermilpd	0x42(%rdx), %ymm5, %ymm6
	vpermilpd	$0x42, %ymm0, %ymm1
	vpermilpd	$0x23, 	(%rsi), %ymm3
	vpermilpd	$0x42, 0x42(%rdi), %ymm3

	vpermilps	%xmm0, %xmm1, %xmm2
	vpermilps	(%rax), %xmm3, %xmm4
	vpermilps	0x42(%rcx), %xmm5, %xmm6
	vpermilps	%ymm0, %ymm1, %ymm2
	vpermilps	(%rbx), %ymm3, %ymm4
	vpermilps	0x42(%rdx), %ymm5, %ymm6
	vpermilps	$0x42, %ymm0, %ymm1
	vpermilps	$0x23, 	(%rsi), %ymm3
	vpermilps	$0x42, 0x42(%rdi), %ymm3

	vpextrb	$0x23, %xmm0, %rax
	vpextrb	$0x23, %xmm1, (%rbx)
	vpextrb	$0x23, %xmm2, 0x16(%rcx)

	vpextrd	$0x23, %xmm1, (%rbx)
	vpextrd	$0x23, %xmm2, 0x16(%rcx)

	vpextrq	$0x23, %xmm0, %rax
	vpextrq	$0x23, %xmm1, (%rbx)
	vpextrq	$0x23, %xmm2, 0x16(%rcx)

	vpextrw	$0x23, %xmm0, %rax
	vpextrw	$0x23, %xmm1, (%rbx)
	vpextrw	$0x23, %xmm2, 0x16(%rcx)

	vphaddd	%xmm0, %xmm1, %xmm2
	vphaddd	(%rax), %xmm3, %xmm4
	vphaddd	0x42(%rcx), %xmm5, %xmm6
	vphaddd	%ymm0, %ymm1, %ymm2
	vphaddd	(%rbx), %ymm3, %ymm4
	vphaddd	0x42(%rdx), %ymm5, %ymm6

	vphaddsw	%xmm0, %xmm1, %xmm2
	vphaddsw	(%rax), %xmm3, %xmm4
	vphaddsw	0x42(%rcx), %xmm5, %xmm6
	vphaddsw	%ymm0, %ymm1, %ymm2
	vphaddsw	(%rbx), %ymm3, %ymm4
	vphaddsw	0x42(%rdx), %ymm5, %ymm6

	vphaddw	%xmm0, %xmm1, %xmm2
	vphaddw	(%rax), %xmm3, %xmm4
	vphaddw	0x42(%rcx), %xmm5, %xmm6
	vphaddw	%ymm0, %ymm1, %ymm2
	vphaddw	(%rbx), %ymm3, %ymm4
	vphaddw	0x42(%rdx), %ymm5, %ymm6

	vphminposuw	%xmm0, %xmm1
	vphminposuw	(%rsi), %xmm3
	vphminposuw	0x42(%rdi), %xmm3

	vphsubd	%xmm0, %xmm1, %xmm2
	vphsubd	(%rax), %xmm3, %xmm4
	vphsubd	0x42(%rcx), %xmm5, %xmm6
	vphsubd	%ymm0, %ymm1, %ymm2
	vphsubd	(%rbx), %ymm3, %ymm4
	vphsubd	0x42(%rdx), %ymm5, %ymm6

	vphsubsw	%xmm0, %xmm1, %xmm2
	vphsubsw	(%rax), %xmm3, %xmm4
	vphsubsw	0x42(%rcx), %xmm5, %xmm6
	vphsubsw	%ymm0, %ymm1, %ymm2
	vphsubsw	(%rbx), %ymm3, %ymm4
	vphsubsw	0x42(%rdx), %ymm5, %ymm6

	vphsubw	%xmm0, %xmm1, %xmm2
	vphsubw	(%rax), %xmm3, %xmm4
	vphsubw	0x42(%rcx), %xmm5, %xmm6
	vphsubw	%ymm0, %ymm1, %ymm2
	vphsubw	(%rbx), %ymm3, %ymm4
	vphsubw	0x42(%rdx), %ymm5, %ymm6

	vpinsrb	$0x20, %rax, %xmm0, %xmm1
	vpinsrb	$0x20, (%rbx), %xmm2, %xmm3
	vpinsrb	$0x20, 0x10(%rbx), %xmm2, %xmm3

	vpinsrd	$0x20, (%rbx), %xmm2, %xmm3
	vpinsrd	$0x20, 0x10(%rbx), %xmm2, %xmm3

	vpinsrq	$0x20, %rax, %xmm0, %xmm1
	vpinsrq	$0x20, (%rbx), %xmm2, %xmm3
	vpinsrq	$0x20, 0x10(%rbx), %xmm2, %xmm3

	vpinsrw	$0x20, %rax, %xmm0, %xmm1
	vpinsrw	$0x20, (%rbx), %xmm2, %xmm3
	vpinsrw	$0x20, 0x10(%rbx), %xmm2, %xmm3

	vpmaddubsw	%xmm0, %xmm1, %xmm2
	vpmaddubsw	(%rax), %xmm3, %xmm4
	vpmaddubsw	0x42(%rcx), %xmm5, %xmm6
	vpmaddubsw	%ymm0, %ymm1, %ymm2
	vpmaddubsw	(%rbx), %ymm3, %ymm4
	vpmaddubsw	0x42(%rdx), %ymm5, %ymm6

	vpmaddwd	%xmm0, %xmm1, %xmm2
	vpmaddwd	(%rax), %xmm3, %xmm4
	vpmaddwd	0x42(%rcx), %xmm5, %xmm6
	vpmaddwd	%ymm0, %ymm1, %ymm2
	vpmaddwd	(%rbx), %ymm3, %ymm4
	vpmaddwd	0x42(%rdx), %ymm5, %ymm6

	vpmaxsb	%xmm0, %xmm1, %xmm2
	vpmaxsb	(%rax), %xmm3, %xmm4
	vpmaxsb	0x42(%rcx), %xmm5, %xmm6
	vpmaxsb	%ymm0, %ymm1, %ymm2
	vpmaxsb	(%rbx), %ymm3, %ymm4
	vpmaxsb	0x42(%rdx), %ymm5, %ymm6

	vpmaxsd	%xmm0, %xmm1, %xmm2
	vpmaxsd	(%rax), %xmm3, %xmm4
	vpmaxsd	0x42(%rcx), %xmm5, %xmm6
	vpmaxsd	%ymm0, %ymm1, %ymm2
	vpmaxsd	(%rbx), %ymm3, %ymm4
	vpmaxsd	0x42(%rdx), %ymm5, %ymm6

	vpmaxsw	%xmm0, %xmm1, %xmm2
	vpmaxsw	(%rax), %xmm3, %xmm4
	vpmaxsw	0x42(%rcx), %xmm5, %xmm6
	vpmaxsw	%ymm0, %ymm1, %ymm2
	vpmaxsw	(%rbx), %ymm3, %ymm4
	vpmaxsw	0x42(%rdx), %ymm5, %ymm6

	vpmaxub	%xmm0, %xmm1, %xmm2
	vpmaxub	(%rax), %xmm3, %xmm4
	vpmaxub	0x42(%rcx), %xmm5, %xmm6
	vpmaxub	%ymm0, %ymm1, %ymm2
	vpmaxub	(%rbx), %ymm3, %ymm4
	vpmaxub	0x42(%rdx), %ymm5, %ymm6

	vpmaxud	%xmm0, %xmm1, %xmm2
	vpmaxud	(%rax), %xmm3, %xmm4
	vpmaxud	0x42(%rcx), %xmm5, %xmm6
	vpmaxud	%ymm0, %ymm1, %ymm2
	vpmaxud	(%rbx), %ymm3, %ymm4
	vpmaxud	0x42(%rdx), %ymm5, %ymm6

	vpmaxuw	%xmm0, %xmm1, %xmm2
	vpmaxuw	(%rax), %xmm3, %xmm4
	vpmaxuw	0x42(%rcx), %xmm5, %xmm6
	vpmaxuw	%ymm0, %ymm1, %ymm2
	vpmaxuw	(%rbx), %ymm3, %ymm4
	vpmaxuw	0x42(%rdx), %ymm5, %ymm6

	vpminsb	%xmm0, %xmm1, %xmm2
	vpminsb	(%rax), %xmm3, %xmm4
	vpminsb	0x42(%rcx), %xmm5, %xmm6
	vpminsb	%ymm0, %ymm1, %ymm2
	vpminsb	(%rbx), %ymm3, %ymm4
	vpminsb	0x42(%rdx), %ymm5, %ymm6

	vpminsd	%xmm0, %xmm1, %xmm2
	vpminsd	(%rax), %xmm3, %xmm4
	vpminsd	0x42(%rcx), %xmm5, %xmm6
	vpminsd	%ymm0, %ymm1, %ymm2
	vpminsd	(%rbx), %ymm3, %ymm4
	vpminsd	0x42(%rdx), %ymm5, %ymm6

	vpminsw	%xmm0, %xmm1, %xmm2
	vpminsw	(%rax), %xmm3, %xmm4
	vpminsw	0x42(%rcx), %xmm5, %xmm6
	vpminsw	%ymm0, %ymm1, %ymm2
	vpminsw	(%rbx), %ymm3, %ymm4
	vpminsw	0x42(%rdx), %ymm5, %ymm6

	vpminub	%xmm0, %xmm1, %xmm2
	vpminub	(%rax), %xmm3, %xmm4
	vpminub	0x42(%rcx), %xmm5, %xmm6
	vpminub	%ymm0, %ymm1, %ymm2
	vpminub	(%rbx), %ymm3, %ymm4
	vpminub	0x42(%rdx), %ymm5, %ymm6

	vpminud	%xmm0, %xmm1, %xmm2
	vpminud	(%rax), %xmm3, %xmm4
	vpminud	0x42(%rcx), %xmm5, %xmm6
	vpminud	%ymm0, %ymm1, %ymm2
	vpminud	(%rbx), %ymm3, %ymm4
	vpminud	0x42(%rdx), %ymm5, %ymm6

	vpminuw	%xmm0, %xmm1, %xmm2
	vpminuw	(%rax), %xmm3, %xmm4
	vpminuw	0x42(%rcx), %xmm5, %xmm6
	vpminuw	%ymm0, %ymm1, %ymm2
	vpminuw	(%rbx), %ymm3, %ymm4
	vpminuw	0x42(%rdx), %ymm5, %ymm6

	vpmovmskb	%xmm0, %rax
	vpmovmskb	%ymm1, %rbx

	vpmovsxbd	%xmm0, %xmm1
	vpmovsxbd	(%rsi), %xmm3
	vpmovsxbd	0x42(%rdi), %xmm3
	vpmovsxbd	%xmm7, %ymm6
	vpmovsxbd	(%rbp), %ymm4
	vpmovsxbd	0x42(%rsp), %ymm4

	vpmovsxbq	%xmm0, %xmm1
	vpmovsxbq	(%rsi), %xmm3
	vpmovsxbq	0x42(%rdi), %xmm3
	vpmovsxbq	%xmm7, %ymm6
	vpmovsxbq	(%rbp), %ymm4
	vpmovsxbq	0x42(%rsp), %ymm4

	vpmovsxbw	%xmm0, %xmm1
	vpmovsxbw	(%rsi), %xmm3
	vpmovsxbw	0x42(%rdi), %xmm3
	vpmovsxbw	%xmm7, %ymm6
	vpmovsxbw	(%rbp), %ymm4
	vpmovsxbw	0x42(%rsp), %ymm4

	vpmovsxdq	%xmm0, %xmm1
	vpmovsxdq	(%rsi), %xmm3
	vpmovsxdq	0x42(%rdi), %xmm3
	vpmovsxdq	%xmm7, %ymm6
	vpmovsxdq	(%rbp), %ymm4
	vpmovsxdq	0x42(%rsp), %ymm4

	vpmovsxwd	%xmm0, %xmm1
	vpmovsxwd	(%rsi), %xmm3
	vpmovsxwd	0x42(%rdi), %xmm3
	vpmovsxwd	%xmm7, %ymm6
	vpmovsxwd	(%rbp), %ymm4
	vpmovsxwd	0x42(%rsp), %ymm4

	vpmovsxwq	%xmm0, %xmm1
	vpmovsxwq	(%rsi), %xmm3
	vpmovsxwq	0x42(%rdi), %xmm3
	vpmovsxwq	%xmm7, %ymm6
	vpmovsxwq	(%rbp), %ymm4
	vpmovsxwq	0x42(%rsp), %ymm4

	vpmovzxbd	%xmm0, %xmm1
	vpmovzxbd	(%rsi), %xmm3
	vpmovzxbd	0x42(%rdi), %xmm3
	vpmovzxbd	%xmm7, %ymm6
	vpmovzxbd	(%rbp), %ymm4
	vpmovzxbd	0x42(%rsp), %ymm4

	vpmovzxbq	%xmm0, %xmm1
	vpmovzxbq	(%rsi), %xmm3
	vpmovzxbq	0x42(%rdi), %xmm3
	vpmovzxbq	%xmm7, %ymm6
	vpmovzxbq	(%rbp), %ymm4
	vpmovzxbq	0x42(%rsp), %ymm4

	vpmovzxbw	%xmm0, %xmm1
	vpmovzxbw	(%rsi), %xmm3
	vpmovzxbw	0x42(%rdi), %xmm3
	vpmovzxbw	%xmm7, %ymm6
	vpmovzxbw	(%rbp), %ymm4
	vpmovzxbw	0x42(%rsp), %ymm4

	vpmovzxdq	%xmm0, %xmm1
	vpmovzxdq	(%rsi), %xmm3
	vpmovzxdq	0x42(%rdi), %xmm3
	vpmovzxdq	%xmm7, %ymm6
	vpmovzxdq	(%rbp), %ymm4
	vpmovzxdq	0x42(%rsp), %ymm4

	vpmovzxwd	%xmm0, %xmm1
	vpmovzxwd	(%rsi), %xmm3
	vpmovzxwd	0x42(%rdi), %xmm3
	vpmovzxwd	%xmm7, %ymm6
	vpmovzxwd	(%rbp), %ymm4
	vpmovzxwd	0x42(%rsp), %ymm4

	vpmovzxwq	%xmm0, %xmm1
	vpmovzxwq	(%rsi), %xmm3
	vpmovzxwq	0x42(%rdi), %xmm3
	vpmovzxwq	%xmm7, %ymm6
	vpmovzxwq	(%rbp), %ymm4
	vpmovzxwq	0x42(%rsp), %ymm4

	vpmuldq	%xmm0, %xmm1, %xmm2
	vpmuldq	(%rax), %xmm3, %xmm4
	vpmuldq	0x42(%rcx), %xmm5, %xmm6
	vpmuldq	%ymm0, %ymm1, %ymm2
	vpmuldq	(%rbx), %ymm3, %ymm4
	vpmuldq	0x42(%rdx), %ymm5, %ymm6

	vpmulhrsw	%xmm0, %xmm1, %xmm2
	vpmulhrsw	(%rax), %xmm3, %xmm4
	vpmulhrsw	0x42(%rcx), %xmm5, %xmm6
	vpmulhrsw	%ymm0, %ymm1, %ymm2
	vpmulhrsw	(%rbx), %ymm3, %ymm4
	vpmulhrsw	0x42(%rdx), %ymm5, %ymm6

	vpmulhuw	%xmm0, %xmm1, %xmm2
	vpmulhuw	(%rax), %xmm3, %xmm4
	vpmulhuw	0x42(%rcx), %xmm5, %xmm6
	vpmulhuw	%ymm0, %ymm1, %ymm2
	vpmulhuw	(%rbx), %ymm3, %ymm4
	vpmulhuw	0x42(%rdx), %ymm5, %ymm6

	vpmulhw	%xmm0, %xmm1, %xmm2
	vpmulhw	(%rax), %xmm3, %xmm4
	vpmulhw	0x42(%rcx), %xmm5, %xmm6
	vpmulhw	%ymm0, %ymm1, %ymm2
	vpmulhw	(%rbx), %ymm3, %ymm4
	vpmulhw	0x42(%rdx), %ymm5, %ymm6

	vpmulld	%xmm0, %xmm1, %xmm2
	vpmulld	(%rax), %xmm3, %xmm4
	vpmulld	0x42(%rcx), %xmm5, %xmm6
	vpmulld	%ymm0, %ymm1, %ymm2
	vpmulld	(%rbx), %ymm3, %ymm4
	vpmulld	0x42(%rdx), %ymm5, %ymm6

	vpmullw	%xmm0, %xmm1, %xmm2
	vpmullw	(%rax), %xmm3, %xmm4
	vpmullw	0x42(%rcx), %xmm5, %xmm6
	vpmullw	%ymm0, %ymm1, %ymm2
	vpmullw	(%rbx), %ymm3, %ymm4
	vpmullw	0x42(%rdx), %ymm5, %ymm6

	vpmuludq	%xmm0, %xmm1, %xmm2
	vpmuludq	(%rax), %xmm3, %xmm4
	vpmuludq	0x42(%rcx), %xmm5, %xmm6
	vpmuludq	%ymm0, %ymm1, %ymm2
	vpmuludq	(%rbx), %ymm3, %ymm4
	vpmuludq	0x42(%rdx), %ymm5, %ymm6

	vpor	%xmm0, %xmm1, %xmm2
	vpor	(%rax), %xmm3, %xmm4
	vpor	0x42(%rcx), %xmm5, %xmm6
	vpor	%ymm0, %ymm1, %ymm2
	vpor	(%rbx), %ymm3, %ymm4
	vpor	0x42(%rdx), %ymm5, %ymm6

	vpsadbw	%xmm0, %xmm1, %xmm2
	vpsadbw	(%rax), %xmm3, %xmm4
	vpsadbw	0x42(%rcx), %xmm5, %xmm6
	vpsadbw	%ymm0, %ymm1, %ymm2
	vpsadbw	(%rbx), %ymm3, %ymm4
	vpsadbw	0x42(%rdx), %ymm5, %ymm6

	vpshufb	%xmm0, %xmm1, %xmm2
	vpshufb	(%rax), %xmm3, %xmm4
	vpshufb	0x42(%rcx), %xmm5, %xmm6
	vpshufb	%ymm0, %ymm1, %ymm2
	vpshufb	(%rbx), %ymm3, %ymm4
	vpshufb	0x42(%rdx), %ymm5, %ymm6

	vpshufd	$0x42, %xmm0, %xmm1
	vpshufd	$0x23, 	(%rsi), %xmm3
	vpshufd	$0x42, 0x42(%rdi), %xmm3
	vpshufd	$0x42, %ymm0, %ymm1
	vpshufd	$0x23, 	(%rsi), %ymm3
	vpshufd	$0x42, 0x42(%rdi), %ymm3

	vpshufhw	$0x42, %xmm0, %xmm1
	vpshufhw	$0x23, 	(%rsi), %xmm3
	vpshufhw	$0x42, 0x42(%rdi), %xmm3
	vpshufhw	$0x42, %ymm0, %ymm1
	vpshufhw	$0x23, 	(%rsi), %ymm3
	vpshufhw	$0x42, 0x42(%rdi), %ymm3

	vpshuflw	$0x42, %xmm0, %xmm1
	vpshuflw	$0x23, 	(%rsi), %xmm3
	vpshuflw	$0x42, 0x42(%rdi), %xmm3
	vpshuflw	$0x42, %ymm0, %ymm1
	vpshuflw	$0x23, 	(%rsi), %ymm3
	vpshuflw	$0x42, 0x42(%rdi), %ymm3

	vpsignb	%xmm0, %xmm1, %xmm2
	vpsignb	(%rax), %xmm3, %xmm4
	vpsignb	0x42(%rcx), %xmm5, %xmm6
	vpsignb	%ymm0, %ymm1, %ymm2
	vpsignb	(%rbx), %ymm3, %ymm4
	vpsignb	0x42(%rdx), %ymm5, %ymm6

	vpsignd	%xmm0, %xmm1, %xmm2
	vpsignd	(%rax), %xmm3, %xmm4
	vpsignd	0x42(%rcx), %xmm5, %xmm6
	vpsignd	%ymm0, %ymm1, %ymm2
	vpsignd	(%rbx), %ymm3, %ymm4
	vpsignd	0x42(%rdx), %ymm5, %ymm6

	vpsignw	%xmm0, %xmm1, %xmm2
	vpsignw	(%rax), %xmm3, %xmm4
	vpsignw	0x42(%rcx), %xmm5, %xmm6
	vpsignw	%ymm0, %ymm1, %ymm2
	vpsignw	(%rbx), %ymm3, %ymm4
	vpsignw	0x42(%rdx), %ymm5, %ymm6

	vpslld	%xmm0, %xmm1, %xmm2
	vpslld	(%rax), %xmm3, %xmm4
	vpslld	0x10(%rbx), %xmm4, %xmm5
	vpslld	$0x4, %xmm6, %xmm7
	vpslld	%xmm0, %ymm1, %ymm2
	vpslld	(%rax), %ymm3, %ymm4
	vpslld	0x10(%rbx), %ymm4, %ymm5
	vpslld	$0x4, %ymm6, %ymm7

	vpslldq	$0x7, %xmm0, %xmm1
	vpslldq	$0x7, %ymm0, %ymm1

	vpsllq	%xmm0, %xmm1, %xmm2
	vpsllq	(%rax), %xmm3, %xmm4
	vpsllq	0x10(%rbx), %xmm4, %xmm5
	vpsllq	$0x4, %xmm6, %xmm7
	vpsllq	%xmm0, %ymm1, %ymm2
	vpsllq	(%rax), %ymm3, %ymm4
	vpsllq	0x10(%rbx), %ymm4, %ymm5
	vpsllq	$0x4, %ymm6, %ymm7

	vpsllw	%xmm0, %xmm1, %xmm2
	vpsllw	(%rax), %xmm3, %xmm4
	vpsllw	0x10(%rbx), %xmm4, %xmm5
	vpsllw	$0x4, %xmm6, %xmm7
	vpsllw	%xmm0, %ymm1, %ymm2
	vpsllw	(%rax), %ymm3, %ymm4
	vpsllw	0x10(%rbx), %ymm4, %ymm5
	vpsllw	$0x4, %ymm6, %ymm7

	vpsrad	%xmm0, %xmm1, %xmm2
	vpsrad	(%rax), %xmm3, %xmm4
	vpsrad	0x10(%rbx), %xmm4, %xmm5
	vpsrad	$0x4, %xmm6, %xmm7
	vpsrad	%xmm0, %ymm1, %ymm2
	vpsrad	(%rax), %ymm3, %ymm4
	vpsrad	0x10(%rbx), %ymm4, %ymm5
	vpsrad	$0x4, %ymm6, %ymm7

	vpsraw	%xmm0, %xmm1, %xmm2
	vpsraw	(%rax), %xmm3, %xmm4
	vpsraw	0x10(%rbx), %xmm4, %xmm5
	vpsraw	$0x4, %xmm6, %xmm7
	vpsraw	%xmm0, %ymm1, %ymm2
	vpsraw	(%rax), %ymm3, %ymm4
	vpsraw	0x10(%rbx), %ymm4, %ymm5
	vpsraw	$0x4, %ymm6, %ymm7

	vpsrld	%xmm0, %xmm1, %xmm2
	vpsrld	(%rax), %xmm3, %xmm4
	vpsrld	0x10(%rbx), %xmm4, %xmm5
	vpsrld	$0x4, %xmm6, %xmm7
	vpsrld	%xmm0, %ymm1, %ymm2
	vpsrld	(%rax), %ymm3, %ymm4
	vpsrld	0x10(%rbx), %ymm4, %ymm5
	vpsrld	$0x4, %ymm6, %ymm7

	vpsrldq	$0x7, %xmm0, %xmm1
	vpsrldq	$0x7, %ymm0, %ymm1

	vpsrlq	%xmm0, %xmm1, %xmm2
	vpsrlq	(%rax), %xmm3, %xmm4
	vpsrlq	0x10(%rbx), %xmm4, %xmm5
	vpsrlq	$0x4, %xmm6, %xmm7
	vpsrlq	%xmm0, %ymm1, %ymm2
	vpsrlq	(%rax), %ymm3, %ymm4
	vpsrlq	0x10(%rbx), %ymm4, %ymm5
	vpsrlq	$0x4, %ymm6, %ymm7

	vpsrlw	%xmm0, %xmm1, %xmm2
	vpsrlw	(%rax), %xmm3, %xmm4
	vpsrlw	0x10(%rbx), %xmm4, %xmm5
	vpsrlw	$0x4, %xmm6, %xmm7
	vpsrlw	%xmm0, %ymm1, %ymm2
	vpsrlw	(%rax), %ymm3, %ymm4
	vpsrlw	0x10(%rbx), %ymm4, %ymm5
	vpsrlw	$0x4, %ymm6, %ymm7

	vpsubb	%xmm0, %xmm1, %xmm2
	vpsubb	(%rax), %xmm3, %xmm4
	vpsubb	0x42(%rcx), %xmm5, %xmm6
	vpsubb	%ymm0, %ymm1, %ymm2
	vpsubb	(%rbx), %ymm3, %ymm4
	vpsubb	0x42(%rdx), %ymm5, %ymm6

	vpsubd	%xmm0, %xmm1, %xmm2
	vpsubd	(%rax), %xmm3, %xmm4
	vpsubd	0x42(%rcx), %xmm5, %xmm6
	vpsubd	%ymm0, %ymm1, %ymm2
	vpsubd	(%rbx), %ymm3, %ymm4
	vpsubd	0x42(%rdx), %ymm5, %ymm6

	vpsubq	%xmm0, %xmm1, %xmm2
	vpsubq	(%rax), %xmm3, %xmm4
	vpsubq	0x42(%rcx), %xmm5, %xmm6
	vpsubq	%ymm0, %ymm1, %ymm2
	vpsubq	(%rbx), %ymm3, %ymm4
	vpsubq	0x42(%rdx), %ymm5, %ymm6

	vpsubsb	%xmm0, %xmm1, %xmm2
	vpsubsb	(%rax), %xmm3, %xmm4
	vpsubsb	0x42(%rcx), %xmm5, %xmm6
	vpsubsb	%ymm0, %ymm1, %ymm2
	vpsubsb	(%rbx), %ymm3, %ymm4
	vpsubsb	0x42(%rdx), %ymm5, %ymm6

	vpsubsw	%xmm0, %xmm1, %xmm2
	vpsubsw	(%rax), %xmm3, %xmm4
	vpsubsw	0x42(%rcx), %xmm5, %xmm6
	vpsubsw	%ymm0, %ymm1, %ymm2
	vpsubsw	(%rbx), %ymm3, %ymm4
	vpsubsw	0x42(%rdx), %ymm5, %ymm6

	vpsubusb	%xmm0, %xmm1, %xmm2
	vpsubusb	(%rax), %xmm3, %xmm4
	vpsubusb	0x42(%rcx), %xmm5, %xmm6
	vpsubusb	%ymm0, %ymm1, %ymm2
	vpsubusb	(%rbx), %ymm3, %ymm4
	vpsubusb	0x42(%rdx), %ymm5, %ymm6

	vpsubusw	%xmm0, %xmm1, %xmm2
	vpsubusw	(%rax), %xmm3, %xmm4
	vpsubusw	0x42(%rcx), %xmm5, %xmm6
	vpsubusw	%ymm0, %ymm1, %ymm2
	vpsubusw	(%rbx), %ymm3, %ymm4
	vpsubusw	0x42(%rdx), %ymm5, %ymm6

	vpsubw	%xmm0, %xmm1, %xmm2
	vpsubw	(%rax), %xmm3, %xmm4
	vpsubw	0x42(%rcx), %xmm5, %xmm6
	vpsubw	%ymm0, %ymm1, %ymm2
	vpsubw	(%rbx), %ymm3, %ymm4
	vpsubw	0x42(%rdx), %ymm5, %ymm6

	vptest	%xmm0, %xmm1
	vptest	(%rsi), %xmm3
	vptest	0x42(%rdi), %xmm3
	vptest	%ymm7, %ymm6
	vptest	(%rbp), %ymm4
	vptest	0x42(%rsp), %ymm4

	vpunpckhbw	%xmm0, %xmm1, %xmm2
	vpunpckhbw	(%rax), %xmm3, %xmm4
	vpunpckhbw	0x42(%rcx), %xmm5, %xmm6
	vpunpckhbw	%ymm0, %ymm1, %ymm2
	vpunpckhbw	(%rbx), %ymm3, %ymm4
	vpunpckhbw	0x42(%rdx), %ymm5, %ymm6

	vpunpckhdq	%xmm0, %xmm1, %xmm2
	vpunpckhdq	(%rax), %xmm3, %xmm4
	vpunpckhdq	0x42(%rcx), %xmm5, %xmm6
	vpunpckhdq	%ymm0, %ymm1, %ymm2
	vpunpckhdq	(%rbx), %ymm3, %ymm4
	vpunpckhdq	0x42(%rdx), %ymm5, %ymm6

	vpunpckhqdq	%xmm0, %xmm1, %xmm2
	vpunpckhqdq	(%rax), %xmm3, %xmm4
	vpunpckhqdq	0x42(%rcx), %xmm5, %xmm6
	vpunpckhqdq	%ymm0, %ymm1, %ymm2
	vpunpckhqdq	(%rbx), %ymm3, %ymm4
	vpunpckhqdq	0x42(%rdx), %ymm5, %ymm6

	vpunpckhwd	%xmm0, %xmm1, %xmm2
	vpunpckhwd	(%rax), %xmm3, %xmm4
	vpunpckhwd	0x42(%rcx), %xmm5, %xmm6
	vpunpckhwd	%ymm0, %ymm1, %ymm2
	vpunpckhwd	(%rbx), %ymm3, %ymm4
	vpunpckhwd	0x42(%rdx), %ymm5, %ymm6

	vpunpcklbw	%xmm0, %xmm1, %xmm2
	vpunpcklbw	(%rax), %xmm3, %xmm4
	vpunpcklbw	0x42(%rcx), %xmm5, %xmm6
	vpunpcklbw	%ymm0, %ymm1, %ymm2
	vpunpcklbw	(%rbx), %ymm3, %ymm4
	vpunpcklbw	0x42(%rdx), %ymm5, %ymm6

	vpunpckldq	%xmm0, %xmm1, %xmm2
	vpunpckldq	(%rax), %xmm3, %xmm4
	vpunpckldq	0x42(%rcx), %xmm5, %xmm6
	vpunpckldq	%ymm0, %ymm1, %ymm2
	vpunpckldq	(%rbx), %ymm3, %ymm4
	vpunpckldq	0x42(%rdx), %ymm5, %ymm6

	vpunpcklqdq	%xmm0, %xmm1, %xmm2
	vpunpcklqdq	(%rax), %xmm3, %xmm4
	vpunpcklqdq	0x42(%rcx), %xmm5, %xmm6
	vpunpcklqdq	%ymm0, %ymm1, %ymm2
	vpunpcklqdq	(%rbx), %ymm3, %ymm4
	vpunpcklqdq	0x42(%rdx), %ymm5, %ymm6

	vpunpcklwd	%xmm0, %xmm1, %xmm2
	vpunpcklwd	(%rax), %xmm3, %xmm4
	vpunpcklwd	0x42(%rcx), %xmm5, %xmm6
	vpunpcklwd	%ymm0, %ymm1, %ymm2
	vpunpcklwd	(%rbx), %ymm3, %ymm4
	vpunpcklwd	0x42(%rdx), %ymm5, %ymm6

	vpxor	%xmm0, %xmm1, %xmm2
	vpxor	(%rax), %xmm3, %xmm4
	vpxor	0x42(%rcx), %xmm5, %xmm6
	vpxor	%ymm0, %ymm1, %ymm2
	vpxor	(%rbx), %ymm3, %ymm4
	vpxor	0x42(%rdx), %ymm5, %ymm6

	vrcpps	%xmm0, %xmm1
	vrcpps	(%rsi), %xmm3
	vrcpps	0x42(%rdi), %xmm3
	vrcpps	%ymm7, %ymm6
	vrcpps	(%rbp), %ymm4
	vrcpps	0x42(%rsp), %ymm4

	vrcpss	%xmm0, %xmm1, %xmm2
	vrcpss	(%rax), %xmm3, %xmm4
	vrcpss	0x42(%rcx), %xmm5, %xmm6

	vroundpd	$0x42, %xmm0, %xmm1
	vroundpd	$0x23, 	(%rsi), %xmm3
	vroundpd	$0x42, 0x42(%rdi), %xmm3
	vroundpd	$0x42, %ymm0, %ymm1
	vroundpd	$0x23, 	(%rsi), %ymm3
	vroundpd	$0x42, 0x42(%rdi), %ymm3

	vroundps	$0x42, %xmm0, %xmm1
	vroundps	$0x23, 	(%rsi), %xmm3
	vroundps	$0x42, 0x42(%rdi), %xmm3
	vroundps	$0x42, %ymm0, %ymm1
	vroundps	$0x23, 	(%rsi), %ymm3
	vroundps	$0x42, 0x42(%rdi), %ymm3

	vroundsd	$0x48, %xmm3, %xmm5, %xmm7
	vroundsd	$0x48, (%rbx), %xmm2, %xmm4
	vroundsd	$0x48, 0x8(%rbx), %xmm1, %xmm6

	vroundss	$0x48, %xmm3, %xmm5, %xmm7
	vroundss	$0x48, (%rbx), %xmm2, %xmm4
	vroundss	$0x48, 0x8(%rbx), %xmm1, %xmm6

	vrsqrtps	%xmm0, %xmm1
	vrsqrtps	(%rsi), %xmm3
	vrsqrtps	0x42(%rdi), %xmm3
	vrsqrtps	%ymm7, %ymm6
	vrsqrtps	(%rbp), %ymm4
	vrsqrtps	0x42(%rsp), %ymm4

	vrsqrtss	%xmm0, %xmm1, %xmm2
	vrsqrtss	(%rax), %xmm3, %xmm4
	vrsqrtss	0x42(%rcx), %xmm5, %xmm6

	vshufpd	$0x48, %xmm3, %xmm5, %xmm7
	vshufpd	$0x48, (%rbx), %xmm2, %xmm4
	vshufpd	$0x48, 0x8(%rbx), %xmm1, %xmm6
	vshufpd	$0x48, %ymm3, %ymm5, %ymm7
	vshufpd	$0x48, (%rbx), %ymm2, %ymm4
	vshufpd	$0x48, 0x8(%rbx), %ymm1, %ymm6

	vshufps	$0x48, %xmm3, %xmm5, %xmm7
	vshufps	$0x48, (%rbx), %xmm2, %xmm4
	vshufps	$0x48, 0x8(%rbx), %xmm1, %xmm6
	vshufps	$0x48, %ymm3, %ymm5, %ymm7
	vshufps	$0x48, (%rbx), %ymm2, %ymm4
	vshufps	$0x48, 0x8(%rbx), %ymm1, %ymm6

	vsqrtpd	%xmm0, %xmm1
	vsqrtpd	(%rsi), %xmm3
	vsqrtpd	0x42(%rdi), %xmm3
	vsqrtpd	%ymm7, %ymm6
	vsqrtpd	(%rbp), %ymm4
	vsqrtpd	0x42(%rsp), %ymm4

	vsqrtps	%xmm0, %xmm1
	vsqrtps	(%rsi), %xmm3
	vsqrtps	0x42(%rdi), %xmm3
	vsqrtps	%ymm7, %ymm6
	vsqrtps	(%rbp), %ymm4
	vsqrtps	0x42(%rsp), %ymm4

	vsqrtsd	%xmm0, %xmm1, %xmm2
	vsqrtsd	(%rax), %xmm3, %xmm4
	vsqrtsd	0x42(%rcx), %xmm5, %xmm6

	vsqrtss	%xmm0, %xmm1, %xmm2
	vsqrtss	(%rax), %xmm3, %xmm4
	vsqrtss	0x42(%rcx), %xmm5, %xmm6

	vstmxcsr	(%rdx)
	vstmxcsr	0x8(%rdx)

	vsubpd	%xmm0, %xmm1, %xmm2
	vsubpd	(%rax), %xmm3, %xmm4
	vsubpd	0x42(%rcx), %xmm5, %xmm6
	vsubpd	%ymm0, %ymm1, %ymm2
	vsubpd	(%rbx), %ymm3, %ymm4
	vsubpd	0x42(%rdx), %ymm5, %ymm6

	vsubps	%xmm0, %xmm1, %xmm2
	vsubps	(%rax), %xmm3, %xmm4
	vsubps	0x42(%rcx), %xmm5, %xmm6
	vsubps	%ymm0, %ymm1, %ymm2
	vsubps	(%rbx), %ymm3, %ymm4
	vsubps	0x42(%rdx), %ymm5, %ymm6

	vsubsd	%xmm0, %xmm1, %xmm2
	vsubsd	(%rax), %xmm3, %xmm4
	vsubsd	0x42(%rcx), %xmm5, %xmm6

	vsubss	%xmm0, %xmm1, %xmm2
	vsubss	(%rax), %xmm3, %xmm4
	vsubss	0x42(%rcx), %xmm5, %xmm6

	vtestpd	%xmm0, %xmm1
	vtestpd	(%rsi), %xmm3
	vtestpd	0x42(%rdi), %xmm3
	vtestpd	%ymm7, %ymm6
	vtestpd	(%rbp), %ymm4
	vtestpd	0x42(%rsp), %ymm4

	vtestps	%xmm0, %xmm1
	vtestps	(%rsi), %xmm3
	vtestps	0x42(%rdi), %xmm3
	vtestps	%ymm7, %ymm6
	vtestps	(%rbp), %ymm4
	vtestps	0x42(%rsp), %ymm4

	vucomisd	%xmm0, %xmm1
	vucomisd	(%rsi), %xmm3
	vucomisd	0x42(%rdi), %xmm3

	vucomiss	%xmm0, %xmm1
	vucomiss	(%rsi), %xmm3
	vucomiss	0x42(%rdi), %xmm3

	vunpckhpd	%xmm0, %xmm1, %xmm2
	vunpckhpd	(%rax), %xmm3, %xmm4
	vunpckhpd	0x42(%rcx), %xmm5, %xmm6
	vunpckhpd	%ymm0, %ymm1, %ymm2
	vunpckhpd	(%rbx), %ymm3, %ymm4
	vunpckhpd	0x42(%rdx), %ymm5, %ymm6

	vunpckhps	%xmm0, %xmm1, %xmm2
	vunpckhps	(%rax), %xmm3, %xmm4
	vunpckhps	0x42(%rcx), %xmm5, %xmm6
	vunpckhps	%ymm0, %ymm1, %ymm2
	vunpckhps	(%rbx), %ymm3, %ymm4
	vunpckhps	0x42(%rdx), %ymm5, %ymm6

	vunpcklpd	%xmm0, %xmm1, %xmm2
	vunpcklpd	(%rax), %xmm3, %xmm4
	vunpcklpd	0x42(%rcx), %xmm5, %xmm6
	vunpcklpd	%ymm0, %ymm1, %ymm2
	vunpcklpd	(%rbx), %ymm3, %ymm4
	vunpcklpd	0x42(%rdx), %ymm5, %ymm6

	vunpcklps	%xmm0, %xmm1, %xmm2
	vunpcklps	(%rax), %xmm3, %xmm4
	vunpcklps	0x42(%rcx), %xmm5, %xmm6
	vunpcklps	%ymm0, %ymm1, %ymm2
	vunpcklps	(%rbx), %ymm3, %ymm4
	vunpcklps	0x42(%rdx), %ymm5, %ymm6

	vxorpd	%xmm0, %xmm1, %xmm2
	vxorpd	(%rax), %xmm3, %xmm4
	vxorpd	0x42(%rcx), %xmm5, %xmm6
	vxorpd	%ymm0, %ymm1, %ymm2
	vxorpd	(%rbx), %ymm3, %ymm4
	vxorpd	0x42(%rdx), %ymm5, %ymm6

	vxorps	%xmm0, %xmm1, %xmm2
	vxorps	(%rax), %xmm3, %xmm4
	vxorps	0x42(%rcx), %xmm5, %xmm6
	vxorps	%ymm0, %ymm1, %ymm2
	vxorps	(%rbx), %ymm3, %ymm4
	vxorps	0x42(%rdx), %ymm5, %ymm6

	vzeroall

	vzeroupper
.size libdis_test, [.-libdis_test]
