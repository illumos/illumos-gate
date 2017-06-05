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
 * Copyright 2017 Joyent, Inc.
 */

/*
 * Basic test for AVX512 mov instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/* bound is not AVX512, but shares the 0x62 opcode on 32-bit. */
	bound		%eax, (%ebx)

	vmovaps		%xmm0, %xmm1
	vmovaps		%xmm2, %xmm3
	vmovaps		%xmm4, %xmm5
	vmovaps		%xmm6, %xmm7

	vmovaps		%ymm0, %ymm1
	vmovaps		%ymm2, %ymm3
	vmovaps		%ymm4, %ymm5
	vmovaps		%ymm6, %ymm7

	vmovaps		%zmm0, %zmm1
	vmovaps		%zmm2, %zmm3
	vmovaps		%zmm4, %zmm5
	vmovaps		%zmm6, %zmm7

	vmovaps		%zmm4, 0x8(%esp)
	vmovaps		0x8(%esp), %zmm3
	vmovaps		%zmm1, %zmm7{%k1}{z}
	vmovaps		%zmm6, %zmm4{%k7}
	vmovaps		%zmm2, %zmm3{z}

	vmovaps		%xmm7, %xmm2{%k3}{z}
	vmovaps		%ymm1, %ymm3{%k5}

	vmovapd		%zmm2, %zmm7

	vmovups		%zmm7, 0x20(%ebp)
	vmovups		0x8(%esp), %zmm7
	vmovups		(%eax), %zmm3{z}

	vmovupd		(%esp), %zmm1{%k2}
	vmovupd		%zmm6, (%esp)

	/* Test offset handling for both disp8*N and full. */
	vmovaps		%zmm5, (%esp)
	vmovaps		%zmm5, 0x20(%esp)
	vmovaps		%zmm4, 0x40(%esp)
	vmovaps		%zmm4, 0x60(%esp)
	vmovaps		%zmm4, 0x80(%esp)
	vmovaps		%zmm4, -0x80(%esp)
	vmovaps		%zmm4, -0x20(%esp)

	vmovaps		(%esp), %zmm5
	vmovaps		0x20(%esp), %zmm5
	vmovaps		0x40(%esp), %zmm5
	vmovaps		0x60(%esp), %zmm5
	vmovaps		0x80(%esp), %zmm5
	vmovaps		-0x80(%esp), %zmm5
	vmovaps		-0x20(%esp), %zmm5

	vmovdqa32	%zmm6, 0x100(%esp)
	vmovdqa32	%ymm6, 0x100(%esp)
	vmovdqa32	%xmm6, 0x100(%esp)
	vmovdqa32	(%eax), %zmm6
	vmovdqa32	(%eax), %ymm6
	vmovdqa32	(%eax), %xmm6

	vmovdqa64	%zmm6, 0x100(%esp)
	vmovdqa64	%ymm6, 0x100(%esp)
	vmovdqa64	%xmm6, 0x100(%esp)
	vmovdqa64	0x800(%esp), %zmm6
	vmovdqa64	0x800(%esp), %ymm6
	vmovdqa64	0x800(%esp), %xmm6

	vmovdqu8	%zmm0, (%esp)
	vmovdqu16	%zmm0, (%esp)
	vmovdqu32	%zmm0, (%esp)
	vmovdqu64	%zmm0, (%esp)
	vmovdqu8	(%esp), %zmm0
	vmovdqu16	(%esp), %zmm0
	vmovdqu32	(%esp), %zmm0
	vmovdqu64	(%esp), %zmm0
.size libdis_test, [.-libdis_test]
