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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * AVX-512 VBMI instruction decoding. This also has tests for some of the vperm
 * variants that are part of AVX512VL.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	vpermb	%xmm0, %xmm1, %xmm2
	vpermb	%xmm10, %xmm11, %xmm12{%k1}
	vpermb	%xmm20, %xmm11, %xmm22{%k2}{z}
	vpermb	(%rax), %xmm1, %xmm2
	vpermb	0x10(%rax), %xmm11, %xmm12{%k1}
	vpermb	0x12345(%rax), %xmm11, %xmm22{%k2}{z}
	vpermb	(%rax,%rbx,4), %xmm1, %xmm2
	vpermb	0x14(%rax,%rcx,8), %xmm11, %xmm12{%k1}

	vpermb	%ymm0, %ymm1, %ymm2
	vpermb	%ymm10, %ymm11, %ymm12{%k1}
	vpermb	%ymm20, %ymm11, %ymm22{%k2}{z}
	vpermb	(%rax), %ymm1, %ymm2
	vpermb	0x10(%rax), %ymm11, %ymm12{%k1}
	vpermb	0x12345(%rax), %ymm11, %ymm22{%k2}{z}
	vpermb	(%rax,%rbx,4), %ymm1, %ymm2
	vpermb	0x14(%rax,%rcx,8), %ymm11, %ymm12{%k1}

	vpermb	%zmm0, %zmm1, %zmm2
	vpermb	%zmm10, %zmm11, %zmm12{%k1}
	vpermb	%zmm20, %zmm11, %zmm22{%k2}{z}
	vpermb	(%rax), %zmm1, %zmm2
	vpermb	0x10(%rax), %zmm11, %zmm12{%k1}
	vpermb	0x12345(%rax), %zmm11, %zmm22{%k2}{z}
	vpermb	(%rax,%rbx,4), %zmm1, %zmm2
	vpermb	0x14(%rax,%rcx,8), %zmm11, %zmm12{%k1}

	vpermw	%xmm0, %xmm1, %xmm2
	vpermw	%xmm10, %xmm11, %xmm12{%k1}
	vpermw	%xmm20, %xmm11, %xmm22{%k2}{z}
	vpermw	(%rax), %xmm1, %xmm2
	vpermw	0x10(%rax), %xmm11, %xmm12{%k1}
	vpermw	0x12345(%rax), %xmm11, %xmm22{%k2}{z}
	vpermw	(%rax,%rbx,4), %xmm1, %xmm2
	vpermw	0x14(%rax,%rcx,8), %xmm11, %xmm12{%k1}

	vpermw	%ymm0, %ymm1, %ymm2
	vpermw	%ymm10, %ymm11, %ymm12{%k1}
	vpermw	%ymm20, %ymm11, %ymm22{%k2}{z}
	vpermw	(%rax), %ymm1, %ymm2
	vpermw	0x10(%rax), %ymm11, %ymm12{%k1}
	vpermw	0x12345(%rax), %ymm11, %ymm22{%k2}{z}
	vpermw	(%rax,%rbx,4), %ymm1, %ymm2
	vpermw	0x14(%rax,%rcx,8), %ymm11, %ymm12{%k1}

	vpermw	%zmm0, %zmm1, %zmm2
	vpermw	%zmm10, %zmm11, %zmm12{%k1}
	vpermw	%zmm20, %zmm11, %zmm22{%k2}{z}
	vpermw	(%rax), %zmm1, %zmm2
	vpermw	0x10(%rax), %zmm11, %zmm12{%k1}
	vpermw	0x12345(%rax), %zmm11, %zmm22{%k2}{z}
	vpermw	(%rax,%rbx,4), %zmm1, %zmm2
	vpermw	0x14(%rax,%rcx,8), %zmm11, %zmm12{%k1}

	vpermi2b	%xmm0, %xmm1, %xmm2
	vpermi2b	%xmm10, %xmm11, %xmm12{%k1}
	vpermi2b	%xmm20, %xmm11, %xmm22{%k2}{z}
	vpermi2b	(%rax), %xmm1, %xmm2
	vpermi2b	0x10(%rax), %xmm11, %xmm12{%k1}
	vpermi2b	0x12345(%rax), %xmm11, %xmm22{%k2}{z}
	vpermi2b	(%rax,%rbx,4), %xmm1, %xmm2
	vpermi2b	0x14(%rax,%rcx,8), %xmm11, %xmm12{%k1}

	vpermi2b	%ymm0, %ymm1, %ymm2
	vpermi2b	%ymm10, %ymm11, %ymm12{%k1}
	vpermi2b	%ymm20, %ymm11, %ymm22{%k2}{z}
	vpermi2b	(%rax), %ymm1, %ymm2
	vpermi2b	0x10(%rax), %ymm11, %ymm12{%k1}
	vpermi2b	0x12345(%rax), %ymm11, %ymm22{%k2}{z}
	vpermi2b	(%rax,%rbx,4), %ymm1, %ymm2
	vpermi2b	0x14(%rax,%rcx,8), %ymm11, %ymm12{%k1}

	vpermi2b	%zmm0, %zmm1, %zmm2
	vpermi2b	%zmm10, %zmm11, %zmm12{%k1}
	vpermi2b	%zmm20, %zmm11, %zmm22{%k2}{z}
	vpermi2b	(%rax), %zmm1, %zmm2
	vpermi2b	0x10(%rax), %zmm11, %zmm12{%k1}
	vpermi2b	0x12345(%rax), %zmm11, %zmm22{%k2}{z}
	vpermi2b	(%rax,%rbx,4), %zmm1, %zmm2
	vpermi2b	0x14(%rax,%rcx,8), %zmm11, %zmm12{%k1}

	vpermi2w	%xmm0, %xmm1, %xmm2
	vpermi2w	%xmm10, %xmm11, %xmm12{%k1}
	vpermi2w	%xmm20, %xmm11, %xmm22{%k2}{z}
	vpermi2w	(%rax), %xmm1, %xmm2
	vpermi2w	0x10(%rax), %xmm11, %xmm12{%k1}
	vpermi2w	0x12345(%rax), %xmm11, %xmm22{%k2}{z}
	vpermi2w	(%rax,%rbx,4), %xmm1, %xmm2
	vpermi2w	0x14(%rax,%rcx,8), %xmm11, %xmm12{%k1}

	vpermi2w	%ymm0, %ymm1, %ymm2
	vpermi2w	%ymm10, %ymm11, %ymm12{%k1}
	vpermi2w	%ymm20, %ymm11, %ymm22{%k2}{z}
	vpermi2w	(%rax), %ymm1, %ymm2
	vpermi2w	0x10(%rax), %ymm11, %ymm12{%k1}
	vpermi2w	0x12345(%rax), %ymm11, %ymm22{%k2}{z}
	vpermi2w	(%rax,%rbx,4), %ymm1, %ymm2
	vpermi2w	0x14(%rax,%rcx,8), %ymm11, %ymm12{%k1}

	vpermi2w	%zmm0, %zmm1, %zmm2
	vpermi2w	%zmm10, %zmm11, %zmm12{%k1}
	vpermi2w	%zmm20, %zmm11, %zmm22{%k2}{z}
	vpermi2w	(%rax), %zmm1, %zmm2
	vpermi2w	0x10(%rax), %zmm11, %zmm12{%k1}
	vpermi2w	0x12345(%rax), %zmm11, %zmm22{%k2}{z}
	vpermi2w	(%rax,%rbx,4), %zmm1, %zmm2
	vpermi2w	0x14(%rax,%rcx,8), %zmm11, %zmm12{%k1}

	vpermi2d	%xmm0, %xmm1, %xmm2
	vpermi2d	%xmm10, %xmm11, %xmm12{%k1}
	vpermi2d	%xmm20, %xmm11, %xmm22{%k2}{z}
	vpermi2d	(%rax), %xmm1, %xmm2
	vpermi2d	0x10(%rax), %xmm11, %xmm12{%k1}
	vpermi2d	0x12345(%rax), %xmm11, %xmm22{%k2}{z}
	vpermi2d	(%rax,%rbx,4), %xmm1, %xmm2
	vpermi2d	0x14(%rax,%rcx,8), %xmm11, %xmm12{%k1}
	vpermi2d	(%rdx){1to4}, %xmm14, %xmm15
	vpermi2d	0x73(%rdx){1to4}, %xmm24, %xmm25{%k4}
	vpermi2d	-0x8(%rdx){1to4}, %xmm30, %xmm31{%k4}{z}

	vpermi2d	%ymm0, %ymm1, %ymm2
	vpermi2d	%ymm10, %ymm11, %ymm12{%k1}
	vpermi2d	%ymm20, %ymm11, %ymm22{%k2}{z}
	vpermi2d	(%rax), %ymm1, %ymm2
	vpermi2d	0x10(%rax), %ymm11, %ymm12{%k1}
	vpermi2d	0x12345(%rax), %ymm11, %ymm22{%k2}{z}
	vpermi2d	(%rax,%rbx,4), %ymm1, %ymm2
	vpermi2d	0x14(%rax,%rcx,8), %ymm11, %ymm12{%k1}
	vpermi2d	(%rdx){1to8}, %ymm14, %ymm15
	vpermi2d	0x73(%rdx){1to8}, %ymm24, %ymm25{%k4}
	vpermi2d	-0x8(%rdx){1to8}, %ymm30, %ymm31{%k4}{z}

	vpermi2d	%zmm0, %zmm1, %zmm2
	vpermi2d	%zmm10, %zmm11, %zmm12{%k1}
	vpermi2d	%zmm20, %zmm11, %zmm22{%k2}{z}
	vpermi2d	(%rax), %zmm1, %zmm2
	vpermi2d	0x10(%rax), %zmm11, %zmm12{%k1}
	vpermi2d	0x12345(%rax), %zmm11, %zmm22{%k2}{z}
	vpermi2d	(%rax,%rbx,4), %zmm1, %zmm2
	vpermi2d	0x14(%rax,%rcx,8), %zmm11, %zmm12{%k1}
	vpermi2d	(%rdx){1to16}, %zmm14, %zmm15
	vpermi2d	0x73(%rdx){1to16}, %zmm24, %zmm25{%k4}
	vpermi2d	-0x8(%rdx){1to16}, %zmm30, %zmm31{%k4}{z}

	vpermi2q	%xmm0, %xmm1, %xmm2
	vpermi2q	%xmm10, %xmm11, %xmm12{%k1}
	vpermi2q	%xmm20, %xmm11, %xmm22{%k2}{z}
	vpermi2q	(%rax), %xmm1, %xmm2
	vpermi2q	0x10(%rax), %xmm11, %xmm12{%k1}
	vpermi2q	0x12345(%rax), %xmm11, %xmm22{%k2}{z}
	vpermi2q	(%rax,%rbx,4), %xmm1, %xmm2
	vpermi2q	0x14(%rax,%rcx,8), %xmm11, %xmm12{%k1}
	vpermi2q	(%rdx){1to2}, %xmm14, %xmm15
	vpermi2q	0x73(%rdx){1to2}, %xmm24, %xmm25{%k4}
	vpermi2q	-0x8(%rdx){1to2}, %xmm30, %xmm31{%k4}{z}

	vpermi2q	%ymm0, %ymm1, %ymm2
	vpermi2q	%ymm10, %ymm11, %ymm12{%k1}
	vpermi2q	%ymm20, %ymm11, %ymm22{%k2}{z}
	vpermi2q	(%rax), %ymm1, %ymm2
	vpermi2q	0x10(%rax), %ymm11, %ymm12{%k1}
	vpermi2q	0x12345(%rax), %ymm11, %ymm22{%k2}{z}
	vpermi2q	(%rax,%rbx,4), %ymm1, %ymm2
	vpermi2q	0x14(%rax,%rcx,8), %ymm11, %ymm12{%k1}
	vpermi2q	(%rdx){1to4}, %ymm14, %ymm15
	vpermi2q	0x73(%rdx){1to4}, %ymm24, %ymm25{%k4}
	vpermi2q	-0x8(%rdx){1to4}, %ymm30, %ymm31{%k4}{z}

	vpermi2q	%zmm0, %zmm1, %zmm2
	vpermi2q	%zmm10, %zmm11, %zmm12{%k1}
	vpermi2q	%zmm20, %zmm11, %zmm22{%k2}{z}
	vpermi2q	(%rax), %zmm1, %zmm2
	vpermi2q	0x10(%rax), %zmm11, %zmm12{%k1}
	vpermi2q	0x12345(%rax), %zmm11, %zmm22{%k2}{z}
	vpermi2q	(%rax,%rbx,4), %zmm1, %zmm2
	vpermi2q	0x14(%rax,%rcx,8), %zmm11, %zmm12{%k1}
	vpermi2q	(%rdx){1to8}, %zmm14, %zmm15
	vpermi2q	0x73(%rdx){1to8}, %zmm24, %zmm25{%k4}
	vpermi2q	-0x8(%rdx){1to8}, %zmm30, %zmm31{%k4}{z}

	vpermt2b	%xmm0, %xmm1, %xmm2
	vpermt2b	%xmm10, %xmm11, %xmm12{%k1}
	vpermt2b	%xmm20, %xmm11, %xmm22{%k2}{z}
	vpermt2b	(%rax), %xmm1, %xmm2
	vpermt2b	0x10(%rax), %xmm11, %xmm12{%k1}
	vpermt2b	0x12345(%rax), %xmm11, %xmm22{%k2}{z}
	vpermt2b	(%rax,%rbx,4), %xmm1, %xmm2
	vpermt2b	0x14(%rax,%rcx,8), %xmm11, %xmm12{%k1}

	vpermt2b	%ymm0, %ymm1, %ymm2
	vpermt2b	%ymm10, %ymm11, %ymm12{%k1}
	vpermt2b	%ymm20, %ymm11, %ymm22{%k2}{z}
	vpermt2b	(%rax), %ymm1, %ymm2
	vpermt2b	0x10(%rax), %ymm11, %ymm12{%k1}
	vpermt2b	0x12345(%rax), %ymm11, %ymm22{%k2}{z}
	vpermt2b	(%rax,%rbx,4), %ymm1, %ymm2
	vpermt2b	0x14(%rax,%rcx,8), %ymm11, %ymm12{%k1}

	vpermt2b	%zmm0, %zmm1, %zmm2
	vpermt2b	%zmm10, %zmm11, %zmm12{%k1}
	vpermt2b	%zmm20, %zmm11, %zmm22{%k2}{z}
	vpermt2b	(%rax), %zmm1, %zmm2
	vpermt2b	0x10(%rax), %zmm11, %zmm12{%k1}
	vpermt2b	0x12345(%rax), %zmm11, %zmm22{%k2}{z}
	vpermt2b	(%rax,%rbx,4), %zmm1, %zmm2
	vpermt2b	0x14(%rax,%rcx,8), %zmm11, %zmm12{%k1}

	vpermt2w	%xmm0, %xmm1, %xmm2
	vpermt2w	%xmm10, %xmm11, %xmm12{%k1}
	vpermt2w	%xmm20, %xmm11, %xmm22{%k2}{z}
	vpermt2w	(%rax), %xmm1, %xmm2
	vpermt2w	0x10(%rax), %xmm11, %xmm12{%k1}
	vpermt2w	0x12345(%rax), %xmm11, %xmm22{%k2}{z}
	vpermt2w	(%rax,%rbx,4), %xmm1, %xmm2
	vpermt2w	0x14(%rax,%rcx,8), %xmm11, %xmm12{%k1}

	vpermt2w	%ymm0, %ymm1, %ymm2
	vpermt2w	%ymm10, %ymm11, %ymm12{%k1}
	vpermt2w	%ymm20, %ymm11, %ymm22{%k2}{z}
	vpermt2w	(%rax), %ymm1, %ymm2
	vpermt2w	0x10(%rax), %ymm11, %ymm12{%k1}
	vpermt2w	0x12345(%rax), %ymm11, %ymm22{%k2}{z}
	vpermt2w	(%rax,%rbx,4), %ymm1, %ymm2
	vpermt2w	0x14(%rax,%rcx,8), %ymm11, %ymm12{%k1}

	vpermt2w	%zmm0, %zmm1, %zmm2
	vpermt2w	%zmm10, %zmm11, %zmm12{%k1}
	vpermt2w	%zmm20, %zmm11, %zmm22{%k2}{z}
	vpermt2w	(%rax), %zmm1, %zmm2
	vpermt2w	0x10(%rax), %zmm11, %zmm12{%k1}
	vpermt2w	0x12345(%rax), %zmm11, %zmm22{%k2}{z}
	vpermt2w	(%rax,%rbx,4), %zmm1, %zmm2
	vpermt2w	0x14(%rax,%rcx,8), %zmm11, %zmm12{%k1}

	vpermt2d	%xmm0, %xmm1, %xmm2
	vpermt2d	%xmm10, %xmm11, %xmm12{%k1}
	vpermt2d	%xmm20, %xmm11, %xmm22{%k2}{z}
	vpermt2d	(%rax), %xmm1, %xmm2
	vpermt2d	0x10(%rax), %xmm11, %xmm12{%k1}
	vpermt2d	0x12345(%rax), %xmm11, %xmm22{%k2}{z}
	vpermt2d	(%rax,%rbx,4), %xmm1, %xmm2
	vpermt2d	0x14(%rax,%rcx,8), %xmm11, %xmm12{%k1}
	vpermt2d	(%rdx){1to4}, %xmm14, %xmm15
	vpermt2d	0x73(%rdx){1to4}, %xmm24, %xmm25{%k4}
	vpermt2d	-0x8(%rdx){1to4}, %xmm30, %xmm31{%k4}{z}

	vpermt2d	%ymm0, %ymm1, %ymm2
	vpermt2d	%ymm10, %ymm11, %ymm12{%k1}
	vpermt2d	%ymm20, %ymm11, %ymm22{%k2}{z}
	vpermt2d	(%rax), %ymm1, %ymm2
	vpermt2d	0x10(%rax), %ymm11, %ymm12{%k1}
	vpermt2d	0x12345(%rax), %ymm11, %ymm22{%k2}{z}
	vpermt2d	(%rax,%rbx,4), %ymm1, %ymm2
	vpermt2d	0x14(%rax,%rcx,8), %ymm11, %ymm12{%k1}
	vpermt2d	(%rdx){1to8}, %ymm14, %ymm15
	vpermt2d	0x73(%rdx){1to8}, %ymm24, %ymm25{%k4}
	vpermt2d	-0x8(%rdx){1to8}, %ymm30, %ymm31{%k4}{z}

	vpermt2d	%zmm0, %zmm1, %zmm2
	vpermt2d	%zmm10, %zmm11, %zmm12{%k1}
	vpermt2d	%zmm20, %zmm11, %zmm22{%k2}{z}
	vpermt2d	(%rax), %zmm1, %zmm2
	vpermt2d	0x10(%rax), %zmm11, %zmm12{%k1}
	vpermt2d	0x12345(%rax), %zmm11, %zmm22{%k2}{z}
	vpermt2d	(%rax,%rbx,4), %zmm1, %zmm2
	vpermt2d	0x14(%rax,%rcx,8), %zmm11, %zmm12{%k1}
	vpermt2d	(%rdx){1to16}, %zmm14, %zmm15
	vpermt2d	0x73(%rdx){1to16}, %zmm24, %zmm25{%k4}
	vpermt2d	-0x8(%rdx){1to16}, %zmm30, %zmm31{%k4}{z}

	vpermt2q	%xmm0, %xmm1, %xmm2
	vpermt2q	%xmm10, %xmm11, %xmm12{%k1}
	vpermt2q	%xmm20, %xmm11, %xmm22{%k2}{z}
	vpermt2q	(%rax), %xmm1, %xmm2
	vpermt2q	0x10(%rax), %xmm11, %xmm12{%k1}
	vpermt2q	0x12345(%rax), %xmm11, %xmm22{%k2}{z}
	vpermt2q	(%rax,%rbx,4), %xmm1, %xmm2
	vpermt2q	0x14(%rax,%rcx,8), %xmm11, %xmm12{%k1}
	vpermt2q	(%rdx){1to2}, %xmm14, %xmm15
	vpermt2q	0x73(%rdx){1to2}, %xmm24, %xmm25{%k4}
	vpermt2q	-0x8(%rdx){1to2}, %xmm30, %xmm31{%k4}{z}

	vpermt2q	%ymm0, %ymm1, %ymm2
	vpermt2q	%ymm10, %ymm11, %ymm12{%k1}
	vpermt2q	%ymm20, %ymm11, %ymm22{%k2}{z}
	vpermt2q	(%rax), %ymm1, %ymm2
	vpermt2q	0x10(%rax), %ymm11, %ymm12{%k1}
	vpermt2q	0x12345(%rax), %ymm11, %ymm22{%k2}{z}
	vpermt2q	(%rax,%rbx,4), %ymm1, %ymm2
	vpermt2q	0x14(%rax,%rcx,8), %ymm11, %ymm12{%k1}
	vpermt2q	(%rdx){1to4}, %ymm14, %ymm15
	vpermt2q	0x73(%rdx){1to4}, %ymm24, %ymm25{%k4}
	vpermt2q	-0x8(%rdx){1to4}, %ymm30, %ymm31{%k4}{z}

	vpermt2q	%zmm0, %zmm1, %zmm2
	vpermt2q	%zmm10, %zmm11, %zmm12{%k1}
	vpermt2q	%zmm20, %zmm11, %zmm22{%k2}{z}
	vpermt2q	(%rax), %zmm1, %zmm2
	vpermt2q	0x10(%rax), %zmm11, %zmm12{%k1}
	vpermt2q	0x12345(%rax), %zmm11, %zmm22{%k2}{z}
	vpermt2q	(%rax,%rbx,4), %zmm1, %zmm2
	vpermt2q	0x14(%rax,%rcx,8), %zmm11, %zmm12{%k1}
	vpermt2q	(%rdx){1to8}, %zmm14, %zmm15
	vpermt2q	0x73(%rdx){1to8}, %zmm24, %zmm25{%k4}
	vpermt2q	-0x8(%rdx){1to8}, %zmm30, %zmm31{%k4}{z}

	vpmultishiftqb	%xmm0, %xmm1, %xmm2
	vpmultishiftqb	%xmm10, %xmm11, %xmm12{%k1}
	vpmultishiftqb	%xmm20, %xmm11, %xmm22{%k2}{z}
	vpmultishiftqb	(%rax), %xmm1, %xmm2
	vpmultishiftqb	0x10(%rax), %xmm11, %xmm12{%k1}
	vpmultishiftqb	0x12345(%rax), %xmm11, %xmm22{%k2}{z}
	vpmultishiftqb	(%rax,%rbx,4), %xmm1, %xmm2
	vpmultishiftqb	0x14(%rax,%rcx,8), %xmm11, %xmm12{%k1}
	vpmultishiftqb	(%rdx){1to2}, %xmm14, %xmm15
	vpmultishiftqb	0x73(%rdx){1to2}, %xmm24, %xmm25{%k4}
	vpmultishiftqb	-0x8(%rdx){1to2}, %xmm30, %xmm31{%k4}{z}

	vpmultishiftqb	%ymm0, %ymm1, %ymm2
	vpmultishiftqb	%ymm10, %ymm11, %ymm12{%k1}
	vpmultishiftqb	%ymm20, %ymm11, %ymm22{%k2}{z}
	vpmultishiftqb	(%rax), %ymm1, %ymm2
	vpmultishiftqb	0x10(%rax), %ymm11, %ymm12{%k1}
	vpmultishiftqb	0x12345(%rax), %ymm11, %ymm22{%k2}{z}
	vpmultishiftqb	(%rax,%rbx,4), %ymm1, %ymm2
	vpmultishiftqb	0x14(%rax,%rcx,8), %ymm11, %ymm12{%k1}
	vpmultishiftqb	(%rdx){1to4}, %ymm14, %ymm15
	vpmultishiftqb	0x73(%rdx){1to4}, %ymm24, %ymm25{%k4}
	vpmultishiftqb	-0x8(%rdx){1to4}, %ymm30, %ymm31{%k4}{z}

	vpmultishiftqb	%zmm0, %zmm1, %zmm2
	vpmultishiftqb	%zmm10, %zmm11, %zmm12{%k1}
	vpmultishiftqb	%zmm20, %zmm11, %zmm22{%k2}{z}
	vpmultishiftqb	(%rax), %zmm1, %zmm2
	vpmultishiftqb	0x10(%rax), %zmm11, %zmm12{%k1}
	vpmultishiftqb	0x12345(%rax), %zmm11, %zmm22{%k2}{z}
	vpmultishiftqb	(%rax,%rbx,4), %zmm1, %zmm2
	vpmultishiftqb	0x14(%rax,%rcx,8), %zmm11, %zmm12{%k1}
	vpmultishiftqb	(%rdx){1to8}, %zmm14, %zmm15
	vpmultishiftqb	0x73(%rdx){1to8}, %zmm24, %zmm25{%k4}
	vpmultishiftqb	-0x8(%rdx){1to8}, %zmm30, %zmm31{%k4}{z}
.size libdis_test, [.-libdis_test]
