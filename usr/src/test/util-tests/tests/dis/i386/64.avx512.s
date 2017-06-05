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
	vmovaps		%xmm0, %xmm1
	vmovaps		%xmm2, %xmm3
	vmovaps		%xmm4, %xmm5
	vmovaps		%xmm6, %xmm7
	vmovaps		%xmm8, %xmm9
	vmovaps		%xmm10, %xmm11
	vmovaps		%xmm12, %xmm13
	vmovaps		%xmm14, %xmm15
	vmovaps		%xmm16, %xmm17
	vmovaps		%xmm18, %xmm19
	vmovaps		%xmm20, %xmm21
	vmovaps		%xmm22, %xmm23
	vmovaps		%xmm24, %xmm25
	vmovaps		%xmm26, %xmm27
	vmovaps		%xmm28, %xmm29
	vmovaps		%xmm30, %xmm31

	vmovaps		%ymm0, %ymm1
	vmovaps		%ymm2, %ymm3
	vmovaps		%ymm4, %ymm5
	vmovaps		%ymm6, %ymm7
	vmovaps		%ymm8, %ymm9
	vmovaps		%ymm10, %ymm11
	vmovaps		%ymm12, %ymm13
	vmovaps		%ymm14, %ymm15
	vmovaps		%ymm16, %ymm17
	vmovaps		%ymm18, %ymm19
	vmovaps		%ymm20, %ymm21
	vmovaps		%ymm22, %ymm23
	vmovaps		%ymm24, %ymm25
	vmovaps		%ymm26, %ymm27
	vmovaps		%ymm28, %ymm29
	vmovaps		%ymm30, %ymm31

	vmovaps		%zmm0, %zmm1
	vmovaps		%zmm2, %zmm3
	vmovaps		%zmm4, %zmm5
	vmovaps		%zmm6, %zmm7
	vmovaps		%zmm8, %zmm9
	vmovaps		%zmm10, %zmm11
	vmovaps		%zmm12, %zmm13
	vmovaps		%zmm14, %zmm15
	vmovaps		%zmm16, %zmm17
	vmovaps		%zmm18, %zmm19
	vmovaps		%zmm20, %zmm21
	vmovaps		%zmm22, %zmm23
	vmovaps		%zmm24, %zmm25
	vmovaps		%zmm26, %zmm27
	vmovaps		%zmm28, %zmm29
	vmovaps		%zmm30, %zmm31

	vmovaps		%zmm24, 0x8(%rsp)
	vmovaps		0x8(%rsp), %zmm31
	vmovaps		%zmm13, %zmm17{%k1}{z}
	vmovaps		%zmm16, %zmm24{%k7}
	vmovaps		%zmm28, %zmm29{z}

	vmovaps		%xmm16, %xmm25
	vmovaps		%xmm7, %xmm20{%k3}{z}
	vmovaps		%ymm1, %ymm16
	vmovaps		%ymm19, %ymm30{%k5}

	vmovapd		%zmm2, %zmm7
	vmovapd		%xmm16, %xmm25
	vmovapd		%ymm16, %ymm29

	vmovups		%zmm7, 0x20(%rbp)
	vmovups		0x8(%rsp), %zmm17
	vmovups		(%rax), %zmm23{z}
	vmovups		%xmm16, %xmm25
	vmovups		%ymm16, %ymm29

	vmovupd		(%r10), %zmm31{%k2}
	vmovupd		%zmm16, (%r11)
	vmovupd		%xmm16, %xmm25
	vmovupd		%ymm16, %ymm29

	/* Test offset handling for both disp8*N and full. */
	vmovaps		%zmm25, (%rsp)
	vmovaps		%zmm25, 0x20(%rsp)
	vmovaps		%zmm24, 0x40(%rsp)
	vmovaps		%zmm24, 0x60(%rsp)
	vmovaps		%zmm24, 0x80(%rsp)
	vmovaps		%zmm24, -0x80(%rsp)
	vmovaps		%zmm24, -0x20(%rsp)

	vmovaps		%ymm24, 0x10(%rsp)
	vmovaps		%ymm24, 0x20(%rsp)
	vmovaps		%ymm24, 0x40(%rsp)

	vmovaps		%xmm24, 0x8(%rsp)
	vmovaps		%xmm24, 0x10(%rsp)
	vmovaps		%xmm24, 0x20(%rsp)

	vmovaps		(%rsp), %zmm25
	vmovaps		0x20(%rsp), %zmm25
	vmovaps		0x40(%rsp), %zmm25
	vmovaps		0x60(%rsp), %zmm25
	vmovaps		0x80(%rsp), %zmm25
	vmovaps		-0x80(%rsp), %zmm25
	vmovaps		-0x20(%rsp), %zmm25

	vmovaps		0x10(%rsp), %ymm25
	vmovaps		0x20(%rsp), %ymm25
	vmovaps		0x40(%rsp), %ymm25

	vmovaps		0x8(%rsp), %xmm25
	vmovaps		0x10(%rsp), %xmm25
	vmovaps		0x20(%rsp), %xmm25

	vmovdqa32	%zmm6, 0x100(%rsp)
	vmovdqa32	%ymm26, 0x100(%rsp)
	vmovdqa32	%xmm16, 0x100(%rsp)
	vmovdqa32	(%rcx), %zmm6
	vmovdqa32	(%rcx), %ymm26
	vmovdqa32	(%rcx), %xmm16

	vmovdqa64	%zmm16, 0x100(%rsp)
	vmovdqa64	%ymm26, 0x100(%rsp)
	vmovdqa64	%xmm16, 0x100(%rsp)
	vmovdqa64	0x800(%rsp), %zmm16
	vmovdqa64	0x800(%rsp), %ymm26
	vmovdqa64	0x800(%rsp), %xmm16

	vmovdqu8	%zmm20, (%rsp)
	vmovdqu16	%zmm20, (%rsp)
	vmovdqu32	%zmm20, (%rsp)
	vmovdqu64	%zmm20, (%rsp)
	vmovdqu8	(%rsp), %zmm20
	vmovdqu16	(%rsp), %zmm20
	vmovdqu32	(%rsp), %zmm20
	vmovdqu64	(%rsp), %zmm20
.size libdis_test, [.-libdis_test]
