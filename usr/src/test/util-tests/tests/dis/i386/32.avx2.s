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
	vbroadcasti128	(%eax), %ymm0
	vextracti128	$0x23, %ymm3, %xmm4
	vextracti128	$0x23, %ymm3, (%ebx)
	vinserti128	$0x42, %xmm2, %ymm3, %ymm4
	vinserti128	$0x42, (%eax), %ymm3, %ymm4
	vmovntdqa	(%eax), %ymm0
	vpblendd	$0x42, %xmm2, %xmm3, %xmm4
	vpblendd	$0x42, (%eax), %xmm3, %xmm4
	vpblendd	$0x42, %ymm2, %ymm3, %ymm4
	vpblendd	$0x42, (%eax), %ymm3, %ymm4
	vpbroadcastb	%xmm0, %xmm1
	vpbroadcastb	(%eax), %xmm2
	vpbroadcastb	%xmm0, %ymm1
	vpbroadcastb	(%eax), %ymm2
	vpbroadcastd	%xmm0, %xmm1
	vpbroadcastd	(%eax), %xmm2
	vpbroadcastd	%xmm0, %ymm1
	vpbroadcastd	(%eax), %ymm2
	vpbroadcastq	%xmm0, %xmm1
	vpbroadcastq	(%eax), %xmm2
	vpbroadcastq	%xmm0, %ymm1
	vpbroadcastq	(%eax), %ymm2
	vpbroadcastw	%xmm0, %xmm1
	vpbroadcastw	(%eax), %xmm2
	vpbroadcastw	%xmm0, %ymm1
	vpbroadcastw	(%eax), %ymm2
	vperm2i128	$0x42, %ymm2, %ymm3, %ymm4
	vperm2i128	$0x42, (%eax), %ymm3, %ymm4
	vpermd		%ymm2, %ymm3, %ymm4
	vpermd		(%eax), %ymm3, %ymm4
	vpermpd		$0x42, %ymm2, %ymm3
	vpermpd		$0x42, (%eax), %ymm3
	vpermps		%ymm1, %ymm2, %ymm3
	vpermps		(%eax), %ymm2, %ymm3
	vpermq		$0x42, %ymm2, %ymm3
	vpermq		$0x42, (%eax), %ymm3
	vpmaskmovd	(%eax), %ymm2, %ymm3
	vpmaskmovq	(%eax), %xmm2, %xmm3
	vpmaskmovq	(%eax), %ymm2, %ymm3
	vpsllvd		%xmm1, %xmm2, %xmm3
	vpsllvd		(%eax), %xmm2, %xmm3
	vpsllvd		%ymm1, %ymm2, %ymm3
	vpsllvd		(%eax), %ymm2, %ymm3
	vpsllvq		%xmm1, %xmm2, %xmm3
	vpsllvq		(%eax), %xmm2, %xmm3
	vpsllvq		%ymm1, %ymm2, %ymm3
	vpsllvq		(%eax), %ymm2, %ymm3
	vpsravd		%xmm1, %xmm2, %xmm3
	vpsravd		(%eax), %xmm2, %xmm3
	vpsravd		%ymm1, %ymm2, %ymm3
	vpsravd		(%eax), %ymm2, %ymm3
	vpsrlvd		%xmm1, %xmm2, %xmm3
	vpsrlvd		(%eax), %xmm2, %xmm3
	vpsrlvd		%ymm1, %ymm2, %ymm3
	vpsrlvd		(%eax), %ymm2, %ymm3
	vpsrlvq		%xmm1, %xmm2, %xmm3
	vpsrlvq		(%eax), %xmm2, %xmm3
	vpsrlvq		%ymm1, %ymm2, %ymm3
	vpsrlvq		(%eax), %ymm2, %ymm3
.size libdis_test, [.-libdis_test]
