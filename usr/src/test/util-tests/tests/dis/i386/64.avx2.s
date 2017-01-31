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
 * Test AVX2 related instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	vbroadcasti128	(%rax), %ymm0
	vextracti128	$0x23, %ymm3, %xmm4
	vextracti128	$0x23, %ymm3, (%rbx)
	vinserti128	$0x42, %xmm2, %ymm3, %ymm4
	vinserti128	$0x42, (%rax), %ymm3, %ymm4
	vmovntdqa	(%rax), %ymm0
	vpblendd	$0x42, %xmm2, %xmm3, %xmm4
	vpblendd	$0x42, (%rax), %xmm3, %xmm4
	vpblendd	$0x42, %ymm2, %ymm3, %ymm4
	vpblendd	$0x42, (%rax), %ymm3, %ymm4
	vpbroadcastb	%xmm0, %xmm1
	vpbroadcastb	(%rax), %xmm2
	vpbroadcastb	%xmm0, %ymm1
	vpbroadcastb	(%rax), %ymm2
	vpbroadcastd	%xmm0, %xmm1
	vpbroadcastd	(%rax), %xmm2
	vpbroadcastd	%xmm0, %ymm1
	vpbroadcastd	(%rax), %ymm2
	vpbroadcastq	%xmm0, %xmm1
	vpbroadcastq	(%rax), %xmm2
	vpbroadcastq	%xmm0, %ymm1
	vpbroadcastq	(%rax), %ymm2
	vpbroadcastw	%xmm0, %xmm1
	vpbroadcastw	(%rax), %xmm2
	vpbroadcastw	%xmm0, %ymm1
	vpbroadcastw	(%rax), %ymm2
	vperm2i128	$0x42, %ymm2, %ymm3, %ymm4
	vperm2i128	$0x42, (%rax), %ymm3, %ymm4
	vpermd		%ymm2, %ymm3, %ymm4
	vpermd		(%rax), %ymm3, %ymm4
	vpermpd		$0x42, %ymm2, %ymm3
	vpermpd		$0x42, (%rax), %ymm3
	vpermps		%ymm1, %ymm2, %ymm3
	vpermps		(%rax), %ymm2, %ymm3
	vpermq		$0x42, %ymm2, %ymm3
	vpermq		$0x42, (%rax), %ymm3
	vpmaskmovd	(%rax), %ymm2, %ymm3
	vpmaskmovq	(%rax), %xmm2, %xmm3
	vpmaskmovq	(%rax), %ymm2, %ymm3
	vpsllvd		%xmm1, %xmm2, %xmm3
	vpsllvd		(%rax), %xmm2, %xmm3
	vpsllvd		%ymm1, %ymm2, %ymm3
	vpsllvd		(%rax), %ymm2, %ymm3
	vpsllvq		%xmm1, %xmm2, %xmm3
	vpsllvq		(%rax), %xmm2, %xmm3
	vpsllvq		%ymm1, %ymm2, %ymm3
	vpsllvq		(%rax), %ymm2, %ymm3
	vpsravd		%xmm1, %xmm2, %xmm3
	vpsravd		(%rax), %xmm2, %xmm3
	vpsravd		%ymm1, %ymm2, %ymm3
	vpsravd		(%rax), %ymm2, %ymm3
	vpsrlvd		%xmm1, %xmm2, %xmm3
	vpsrlvd		(%rax), %xmm2, %xmm3
	vpsrlvd		%ymm1, %ymm2, %ymm3
	vpsrlvd		(%rax), %ymm2, %ymm3
	vpsrlvq		%xmm1, %xmm2, %xmm3
	vpsrlvq		(%rax), %xmm2, %xmm3
	vpsrlvq		%ymm1, %ymm2, %ymm3
	vpsrlvq		(%rax), %ymm2, %ymm3
.size libdis_test, [.-libdis_test]
