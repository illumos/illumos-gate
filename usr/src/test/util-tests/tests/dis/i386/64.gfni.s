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
 * Copyright 2020 Robert Mustacchi
 */

/*
 * Test GFNI related instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/* SSE Form */
	gf2p8affineinvqb	$0x23, %xmm0, %xmm1
	gf2p8affineinvqb	$0x51, (%rax), %xmm2
	gf2p8affineinvqb	$0x19, 0x12(%rbx), %xmm3
	gf2p8affineinvqb	$0x77, 0x12(%r10, %r12, 4), %xmm4

	gf2p8affineqb		$0x23, %xmm7, %xmm6
	gf2p8affineqb		$0x51, (%rax), %xmm5
	gf2p8affineqb		$0x19, 0x12(%rbx), %xmm4
	gf2p8affineqb		$0x77, 0x12(%r10, %r12, 4), %xmm3

	gf2p8mulb		%xmm2, %xmm3
	gf2p8mulb		(%rax), %xmm4
	gf2p8mulb		0x12(%rbx), %xmm3
	gf2p8mulb		0x17(%r10, %r12, 4), %xmm2

	/* VEX Form - xmm */
	vgf2p8affineinvqb	$0x23, %xmm0, %xmm1, %xmm5
	vgf2p8affineinvqb	$0x51, (%rax), %xmm2, %xmm6
	vgf2p8affineinvqb	$0x19, 0x12(%rbx), %xmm3, %xmm7
	vgf2p8affineinvqb	$0x77, 0x12(%r10, %r12, 4), %xmm4, %xmm0

	vgf2p8affineqb		$0x23, %xmm7, %xmm6, %xmm0
	vgf2p8affineqb		$0x51, (%rax), %xmm5, %xmm1
	vgf2p8affineqb		$0x19, 0x12(%rbx), %xmm4, %xmm2
	vgf2p8affineqb		$0x77, 0x12(%r10, %r12, 4), %xmm3, %xmm6

	vgf2p8mulb		%xmm2, %xmm3, %xmm0
	vgf2p8mulb		(%rax), %xmm4, %xmm1
	vgf2p8mulb		0x12(%rbx), %xmm3, %xmm2
	vgf2p8mulb		0x17(%r10, %r12, 4), %xmm2, %xmm3

	/* VEX Form - ymm */
	vgf2p8affineinvqb	$0x23, %ymm0, %ymm1, %ymm5
	vgf2p8affineinvqb	$0x51, (%rax), %ymm2, %ymm6
	vgf2p8affineinvqb	$0x19, 0x12(%rbx), %ymm3, %ymm7
	vgf2p8affineinvqb	$0x77, 0x12(%r10, %r12, 4), %ymm4, %ymm0

	vgf2p8affineqb		$0x23, %ymm7, %ymm6, %ymm0
	vgf2p8affineqb		$0x51, (%rax), %ymm5, %ymm1
	vgf2p8affineqb		$0x19, 0x12(%rbx), %ymm4, %ymm2
	vgf2p8affineqb		$0x77, 0x12(%r10, %r12, 4), %ymm3, %ymm6

	vgf2p8mulb		%ymm2, %ymm3, %ymm0
	vgf2p8mulb		(%rax), %ymm4, %ymm1
	vgf2p8mulb		0x12(%rbx), %ymm3, %ymm2
	vgf2p8mulb		0x17(%r10, %r12, 4), %ymm2, %ymm3

	/* EVEX Form - basic zmm */
	vgf2p8affineinvqb	$0x23, %zmm0, %zmm1, %zmm5
	vgf2p8affineinvqb	$0x51, (%rax), %zmm2, %zmm6
	vgf2p8affineinvqb	$0x19, 0x12(%rbx), %zmm3, %zmm7
	vgf2p8affineinvqb	$0x77, 0x12(%r10, %r12, 4), %zmm4, %zmm0

	vgf2p8affineqb		$0x23, %zmm7, %zmm6, %zmm0
	vgf2p8affineqb		$0x51, (%rax), %zmm5, %zmm1
	vgf2p8affineqb		$0x19, 0x12(%rbx), %zmm4, %zmm2
	vgf2p8affineqb		$0x77, 0x12(%r10, %r12, 4), %zmm3, %zmm6

	vgf2p8mulb		%zmm2, %zmm3, %zmm0
	vgf2p8mulb		(%rax), %zmm4, %zmm1
	vgf2p8mulb		0x12(%rbx), %zmm3, %zmm2
	vgf2p8mulb		0x17(%r10, %r12, 4), %zmm2, %zmm3

	/* EVEX Form - zmm, masks */
	vgf2p8affineinvqb	$0x23, %zmm0, %zmm1, %zmm5{%k1}
	vgf2p8affineinvqb	$0x23, %zmm0, %zmm1, %zmm5{%k2}{z}
	vgf2p8affineinvqb	$0x51, (%rax), %zmm2, %zmm6{%k3}
	vgf2p8affineinvqb	$0x51, (%rax), %zmm2, %zmm6{%k4}{z}
	vgf2p8affineinvqb	$0x19, 0x12(%rbx), %zmm3, %zmm7{%k5}
	vgf2p8affineinvqb	$0x19, 0x12(%rbx), %zmm3, %zmm7{%k6}{z}
	vgf2p8affineinvqb	$0x77, 0x12(%r10, %r12, 4), %zmm4, %zmm0{%k7}
	vgf2p8affineinvqb	$0x77, 0x12(%r10, %r12, 4), %zmm4, %zmm0{%k7}{z}

	vgf2p8affineqb		$0x23, %zmm7, %zmm6, %zmm0{%k7}
	vgf2p8affineqb		$0x23, %zmm7, %zmm6, %zmm0{%k6}{z}
	vgf2p8affineqb		$0x51, (%rax), %zmm5, %zmm1{%k5}
	vgf2p8affineqb		$0x51, (%rax), %zmm5, %zmm1{%k4}{z}
	vgf2p8affineqb		$0x19, 0x12(%rbx), %zmm4, %zmm2{%k3}
	vgf2p8affineqb		$0x19, 0x12(%rbx), %zmm4, %zmm2{%k2}{z}
	vgf2p8affineqb		$0x77, 0x12(%r10, %r12, 4), %zmm3, %zmm6{%k1}
	vgf2p8affineqb		$0x77, 0x12(%r10, %r12, 4), %zmm3, %zmm6{%k2}{z}

	vgf2p8mulb		%zmm2, %zmm3, %zmm0{%k3}
	vgf2p8mulb		%zmm2, %zmm3, %zmm0{%k2}{z}
	vgf2p8mulb		(%rax), %zmm4, %zmm1{%k4}
	vgf2p8mulb		(%rax), %zmm4, %zmm1{%k5}{z}
	vgf2p8mulb		0x12(%rbx), %zmm3, %zmm2{%k1}
	vgf2p8mulb		0x12(%rbx), %zmm3, %zmm2{%k2}{z}
	vgf2p8mulb		0x17(%r10, %r12, 4), %zmm2, %zmm3{%k7}
	vgf2p8mulb		0x17(%r10, %r12, 4), %zmm2, %zmm3{%k6}{z}

	/* EVEX Form - ymm, masks */
	vgf2p8affineinvqb	$0x23, %ymm0, %ymm1, %ymm5{%k1}
	vgf2p8affineinvqb	$0x23, %ymm0, %ymm1, %ymm5{%k2}{z}
	vgf2p8affineinvqb	$0x51, (%rax), %ymm2, %ymm6{%k3}
	vgf2p8affineinvqb	$0x51, (%rax), %ymm2, %ymm6{%k4}{z}
	vgf2p8affineinvqb	$0x19, 0x12(%rbx), %ymm3, %ymm7{%k5}
	vgf2p8affineinvqb	$0x19, 0x12(%rbx), %ymm3, %ymm7{%k6}{z}
	vgf2p8affineinvqb	$0x77, 0x12(%r10, %r12, 4), %ymm4, %ymm0{%k7}
	vgf2p8affineinvqb	$0x77, 0x12(%r10, %r12, 4), %ymm4, %ymm0{%k7}{z}

	vgf2p8affineqb		$0x23, %ymm7, %ymm6, %ymm0{%k7}
	vgf2p8affineqb		$0x23, %ymm7, %ymm6, %ymm0{%k6}{z}
	vgf2p8affineqb		$0x51, (%rax), %ymm5, %ymm1{%k5}
	vgf2p8affineqb		$0x51, (%rax), %ymm5, %ymm1{%k4}{z}
	vgf2p8affineqb		$0x19, 0x12(%rbx), %ymm4, %ymm2{%k3}
	vgf2p8affineqb		$0x19, 0x12(%rbx), %ymm4, %ymm2{%k2}{z}
	vgf2p8affineqb		$0x77, 0x12(%r10, %r12, 4), %ymm3, %ymm6{%k1}
	vgf2p8affineqb		$0x77, 0x12(%r10, %r12, 4), %ymm3, %ymm6{%k2}{z}

	vgf2p8mulb		%ymm2, %ymm3, %ymm0{%k3}
	vgf2p8mulb		%ymm2, %ymm3, %ymm0{%k2}{z}
	vgf2p8mulb		(%rax), %ymm4, %ymm1{%k4}
	vgf2p8mulb		(%rax), %ymm4, %ymm1{%k5}{z}
	vgf2p8mulb		0x12(%rbx), %ymm3, %ymm2{%k1}
	vgf2p8mulb		0x12(%rbx), %ymm3, %ymm2{%k2}{z}
	vgf2p8mulb		0x17(%r10, %r12, 4), %ymm2, %ymm3{%k7}
	vgf2p8mulb		0x17(%r10, %r12, 4), %ymm2, %ymm3{%k6}{z}

	/* EVEX Form - ymm, masks */
	vgf2p8affineinvqb	$0x23, %xmm0, %xmm1, %xmm5{%k1}
	vgf2p8affineinvqb	$0x23, %xmm0, %xmm1, %xmm5{%k2}{z}
	vgf2p8affineinvqb	$0x51, (%rax), %xmm2, %xmm6{%k3}
	vgf2p8affineinvqb	$0x51, (%rax), %xmm2, %xmm6{%k4}{z}
	vgf2p8affineinvqb	$0x19, 0x12(%rbx), %xmm3, %xmm7{%k5}
	vgf2p8affineinvqb	$0x19, 0x12(%rbx), %xmm3, %xmm7{%k6}{z}
	vgf2p8affineinvqb	$0x77, 0x12(%r10, %r12, 4), %xmm4, %xmm0{%k7}
	vgf2p8affineinvqb	$0x77, 0x12(%r10, %r12, 4), %xmm4, %xmm0{%k7}{z}

	vgf2p8affineqb		$0x23, %xmm7, %xmm6, %xmm0{%k7}
	vgf2p8affineqb		$0x23, %xmm7, %xmm6, %xmm0{%k6}{z}
	vgf2p8affineqb		$0x51, (%rax), %xmm5, %xmm1{%k5}
	vgf2p8affineqb		$0x51, (%rax), %xmm5, %xmm1{%k4}{z}
	vgf2p8affineqb		$0x19, 0x12(%rbx), %xmm4, %xmm2{%k3}
	vgf2p8affineqb		$0x19, 0x12(%rbx), %xmm4, %xmm2{%k2}{z}
	vgf2p8affineqb		$0x77, 0x12(%r10, %r12, 4), %xmm3, %xmm6{%k1}
	vgf2p8affineqb		$0x77, 0x12(%r10, %r12, 4), %xmm3, %xmm6{%k2}{z}

	vgf2p8mulb		%xmm2, %xmm3, %xmm0{%k3}
	vgf2p8mulb		%xmm2, %xmm3, %xmm0{%k2}{z}
	vgf2p8mulb		(%rax), %xmm4, %xmm1{%k4}
	vgf2p8mulb		(%rax), %xmm4, %xmm1{%k5}{z}
	vgf2p8mulb		0x12(%rbx), %xmm3, %xmm2{%k1}
	vgf2p8mulb		0x12(%rbx), %xmm3, %xmm2{%k2}{z}
	vgf2p8mulb		0x17(%r10, %r12, 4), %xmm2, %xmm3{%k7}
	vgf2p8mulb		0x17(%r10, %r12, 4), %xmm2, %xmm3{%k6}{z}
.size libdis_test, [.-libdis_test]
