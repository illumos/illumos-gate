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
 * Basic test for AVX512 instructions
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

	vandnpd	%xmm0, %xmm1, %xmm2{z}
	vandnpd	(%eax), %xmm3, %xmm4{z}
	vandnpd	0x42(%ecx), %xmm5, %xmm6{z}
	vandnpd	%ymm0, %ymm1, %ymm2{z}
	vandnpd	(%ebx), %ymm3, %ymm4{z}
	vandnpd	0x42(%edx), %ymm5, %ymm6{z}
	vandnpd	%zmm0, %zmm1, %zmm2
	vandnpd	(%ebx), %zmm3, %zmm4
	vandnpd	0x42(%edx), %zmm5, %zmm6

	vandnps	%xmm0, %xmm1, %xmm2{z}
	vandnps	(%eax), %xmm3, %xmm4{z}
	vandnps	0x42(%ecx), %xmm5, %xmm6{z}
	vandnps	%ymm0, %ymm1, %ymm2{z}
	vandnps	(%ebx), %ymm3, %ymm4{z}
	vandnps	0x42(%edx), %ymm5, %ymm6{z}
	vandnps	%zmm0, %zmm1, %zmm2
	vandnps	(%ebx), %zmm3, %zmm4
	vandnps	0x42(%edx), %zmm5, %zmm6

	vandpd	%xmm0, %xmm1, %xmm2{z}
	vandpd	(%eax), %xmm3, %xmm4{z}
	vandpd	0x42(%ecx), %xmm5, %xmm6{z}
	vandpd	%ymm0, %ymm1, %ymm2{z}
	vandpd	(%ebx), %ymm3, %ymm4{z}
	vandpd	0x42(%edx), %ymm5, %ymm6{z}
	vandpd	%zmm0, %zmm1, %zmm2
	vandpd	(%ebx), %zmm3, %zmm4
	vandpd	0x42(%edx), %zmm5, %zmm6

	vandps	%xmm0, %xmm1, %xmm2{z}
	vandps	(%eax), %xmm3, %xmm4{z}
	vandps	0x42(%ecx), %xmm5, %xmm6{z}
	vandps	%ymm0, %ymm1, %ymm2{z}
	vandps	(%ebx), %ymm3, %ymm4{z}
	vandps	0x42(%edx), %ymm5, %ymm6{z}
	vandps	%zmm0, %zmm1, %zmm2
	vandps	(%ebx), %zmm3, %zmm4
	vandps	0x42(%edx), %zmm5, %zmm6

	vpandd	%xmm0, %xmm1, %xmm2
	vpandd	(%eax), %xmm3, %xmm4
	vpandd	0x42(%ecx), %xmm5, %xmm6
	vpandd	%ymm0, %ymm1, %ymm2
	vpandd	(%ebx), %ymm3, %ymm4
	vpandd	0x42(%edx), %ymm5, %ymm6
	vpandd	%zmm0, %zmm1, %zmm2
	vpandd	(%ebx), %zmm3, %zmm4
	vpandd	0x42(%edx), %zmm5, %zmm6

	vpandq	%xmm0, %xmm1, %xmm2
	vpandq	(%eax), %xmm3, %xmm4
	vpandq	0x42(%ecx), %xmm5, %xmm6
	vpandq	%ymm0, %ymm1, %ymm2
	vpandq	(%ebx), %ymm3, %ymm4
	vpandq	0x42(%edx), %ymm5, %ymm6
	vpandq	%zmm0, %zmm1, %zmm2
	vpandq	(%ebx), %zmm3, %zmm4
	vpandq	0x42(%edx), %zmm5, %zmm6

	vpandnd	%xmm0, %xmm1, %xmm2
	vpandnd	(%eax), %xmm3, %xmm4
	vpandnd	0x42(%ecx), %xmm5, %xmm6
	vpandnd	%ymm0, %ymm1, %ymm2
	vpandnd	(%ebx), %ymm3, %ymm4
	vpandnd	0x42(%edx), %ymm5, %ymm6
	vpandnd	%zmm0, %zmm1, %zmm2
	vpandnd	(%ebx), %zmm3, %zmm4
	vpandnd	0x42(%edx), %zmm5, %zmm6

	vpandnq	%xmm0, %xmm1, %xmm2
	vpandnq	(%eax), %xmm3, %xmm4
	vpandnq	0x42(%ecx), %xmm5, %xmm6
	vpandnq	%ymm0, %ymm1, %ymm2
	vpandnq	(%ebx), %ymm3, %ymm4
	vpandnq	0x42(%edx), %ymm5, %ymm6
	vpandnq	%zmm0, %zmm1, %zmm2
	vpandnq	(%ebx), %zmm3, %zmm4
	vpandnq	0x42(%edx), %zmm5, %zmm6

	vorpd	%xmm0, %xmm1, %xmm2{z}
	vorpd	(%eax), %xmm3, %xmm4{z}
	vorpd	0x42(%ecx), %xmm5, %xmm6{z}
	vorpd	%ymm0, %ymm1, %ymm2{z}
	vorpd	(%ebx), %ymm3, %ymm4{z}
	vorpd	0x42(%edx), %ymm5, %ymm6{z}
	vorpd	%zmm0, %zmm1, %zmm2
	vorpd	(%eax), %zmm3, %zmm4
	vorpd	0x42(%ecx), %zmm5, %zmm6

	vorps	%xmm0, %xmm1, %xmm2{z}
	vorps	(%eax), %xmm3, %xmm4{z}
	vorps	0x42(%ecx), %xmm5, %xmm6{z}
	vorps	%ymm0, %ymm1, %ymm2{z}
	vorps	(%ebx), %ymm3, %ymm4{z}
	vorps	0x42(%edx), %ymm5, %ymm6{z}
	vorps	%zmm0, %zmm1, %zmm2
	vorps	(%eax), %zmm3, %zmm4
	vorps	0x42(%ecx), %zmm5, %zmm6

	vpord	%xmm0, %xmm1, %xmm2
	vpord	(%eax), %xmm3, %xmm4
	vpord	0x42(%ecx), %xmm5, %xmm6
	vpord	%ymm0, %ymm1, %ymm2
	vpord	(%ebx), %ymm3, %ymm4
	vpord	0x42(%edx), %ymm5, %ymm6
	vpord	%zmm0, %zmm1, %zmm2
	vpord	(%eax), %zmm3, %zmm4
	vpord	0x42(%ecx), %zmm5, %zmm6

	vporq	%xmm0, %xmm1, %xmm2
	vporq	(%eax), %xmm3, %xmm4
	vporq	0x42(%ecx), %xmm5, %xmm6
	vporq	%ymm0, %ymm1, %ymm2
	vporq	(%ebx), %ymm3, %ymm4
	vporq	0x42(%edx), %ymm5, %ymm6
	vporq	%zmm0, %zmm1, %zmm2
	vporq	(%eax), %zmm3, %zmm4
	vporq	0x42(%ecx), %zmm5, %zmm6

	vpxord	%xmm0, %xmm1, %xmm2
	vpxord	(%eax), %xmm3, %xmm4
	vpxord	0x42(%ecx), %xmm5, %xmm6
	vpxord	%ymm0, %ymm1, %ymm2
	vpxord	(%ebx), %ymm3, %ymm4
	vpxord	0x42(%edx), %ymm5, %ymm6
	vpxord	%zmm0, %zmm1, %zmm2
	vpxord	(%eax), %zmm3, %zmm4
	vpxord	0x42(%ecx), %zmm5, %zmm6

	vpxorq	%xmm0, %xmm1, %xmm2
	vpxorq	(%eax), %xmm3, %xmm4
	vpxorq	0x42(%ecx), %xmm5, %xmm6
	vpxorq	%ymm0, %ymm1, %ymm2
	vpxorq	(%ebx), %ymm3, %ymm4
	vpxorq	0x42(%edx), %ymm5, %ymm6
	vpxorq	%zmm0, %zmm1, %zmm2
	vpxorq	(%eax), %zmm3, %zmm4
	vpxorq	0x42(%ecx), %zmm5, %zmm6

	vxorpd	%xmm0, %xmm1, %xmm2{z}
	vxorpd	(%eax), %xmm3, %xmm4{z}
	vxorpd	0x42(%ecx), %xmm5, %xmm6{z}
	vxorpd	%ymm0, %ymm1, %ymm2{z}
	vxorpd	(%ebx), %ymm3, %ymm4{z}
	vxorpd	0x42(%edx), %ymm5, %ymm6{z}
	vxorpd	%zmm0, %zmm1, %zmm2
	vxorpd	(%ebx), %zmm3, %zmm4
	vxorpd	0x42(%edx), %zmm5, %zmm6

	vxorps	%xmm0, %xmm1, %xmm2{z}
	vxorps	(%eax), %xmm3, %xmm4{z}
	vxorps	0x42(%ecx), %xmm5, %xmm6{z}
	vxorps	%ymm0, %ymm1, %ymm2{z}
	vxorps	(%ebx), %ymm3, %ymm4{z}
	vxorps	0x42(%edx), %ymm5, %ymm6{z}
	vxorps	%zmm0, %zmm1, %zmm2
	vxorps	(%ebx), %zmm3, %zmm4
	vxorps	0x42(%edx), %zmm5, %zmm6
.size libdis_test, [.-libdis_test]
