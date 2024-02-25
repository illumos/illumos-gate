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
	vpermb	%xmm7, %xmm4, %xmm5{%k1}
	vpermb	%xmm2, %xmm4, %xmm3{%k2}{z}
	vpermb	(%eax), %xmm1, %xmm2
	vpermb	0x10(%eax), %xmm4, %xmm5{%k1}
	vpermb	0x12345(%eax), %xmm4, %xmm3{%k2}{z}
	vpermb	(%eax,%ebx,4), %xmm1, %xmm2
	vpermb	0x14(%eax,%ecx,8), %xmm4, %xmm5{%k1}

	vpermb	%ymm0, %ymm1, %ymm2
	vpermb	%ymm7, %ymm4, %ymm5{%k1}
	vpermb	%ymm2, %ymm4, %ymm3{%k2}{z}
	vpermb	(%eax), %ymm1, %ymm2
	vpermb	0x10(%eax), %ymm4, %ymm5{%k1}
	vpermb	0x12345(%eax), %ymm4, %ymm3{%k2}{z}
	vpermb	(%eax,%ebx,4), %ymm1, %ymm2
	vpermb	0x14(%eax,%ecx,8), %ymm4, %ymm5{%k1}

	vpermb	%zmm0, %zmm1, %zmm2
	vpermb	%zmm7, %zmm4, %zmm5{%k1}
	vpermb	%zmm2, %zmm4, %zmm3{%k2}{z}
	vpermb	(%eax), %zmm1, %zmm2
	vpermb	0x10(%eax), %zmm4, %zmm5{%k1}
	vpermb	0x12345(%eax), %zmm4, %zmm3{%k2}{z}
	vpermb	(%eax,%ebx,4), %zmm1, %zmm2
	vpermb	0x14(%eax,%ecx,8), %zmm4, %zmm5{%k1}

	vpermw	%xmm0, %xmm1, %xmm2
	vpermw	%xmm7, %xmm4, %xmm5{%k1}
	vpermw	%xmm2, %xmm4, %xmm3{%k2}{z}
	vpermw	(%eax), %xmm1, %xmm2
	vpermw	0x10(%eax), %xmm4, %xmm5{%k1}
	vpermw	0x12345(%eax), %xmm4, %xmm3{%k2}{z}
	vpermw	(%eax,%ebx,4), %xmm1, %xmm2
	vpermw	0x14(%eax,%ecx,8), %xmm4, %xmm5{%k1}

	vpermw	%ymm0, %ymm1, %ymm2
	vpermw	%ymm7, %ymm4, %ymm5{%k1}
	vpermw	%ymm2, %ymm4, %ymm3{%k2}{z}
	vpermw	(%eax), %ymm1, %ymm2
	vpermw	0x10(%eax), %ymm4, %ymm5{%k1}
	vpermw	0x12345(%eax), %ymm4, %ymm3{%k2}{z}
	vpermw	(%eax,%ebx,4), %ymm1, %ymm2
	vpermw	0x14(%eax,%ecx,8), %ymm4, %ymm5{%k1}

	vpermw	%zmm0, %zmm1, %zmm2
	vpermw	%zmm7, %zmm4, %zmm5{%k1}
	vpermw	%zmm2, %zmm4, %zmm3{%k2}{z}
	vpermw	(%eax), %zmm1, %zmm2
	vpermw	0x10(%eax), %zmm4, %zmm5{%k1}
	vpermw	0x12345(%eax), %zmm4, %zmm3{%k2}{z}
	vpermw	(%eax,%ebx,4), %zmm1, %zmm2
	vpermw	0x14(%eax,%ecx,8), %zmm4, %zmm5{%k1}

	vpermi2b	%xmm0, %xmm1, %xmm2
	vpermi2b	%xmm7, %xmm4, %xmm5{%k1}
	vpermi2b	%xmm2, %xmm4, %xmm3{%k2}{z}
	vpermi2b	(%eax), %xmm1, %xmm2
	vpermi2b	0x10(%eax), %xmm4, %xmm5{%k1}
	vpermi2b	0x12345(%eax), %xmm4, %xmm3{%k2}{z}
	vpermi2b	(%eax,%ebx,4), %xmm1, %xmm2
	vpermi2b	0x14(%eax,%ecx,8), %xmm4, %xmm5{%k1}

	vpermi2b	%ymm0, %ymm1, %ymm2
	vpermi2b	%ymm7, %ymm4, %ymm5{%k1}
	vpermi2b	%ymm2, %ymm4, %ymm3{%k2}{z}
	vpermi2b	(%eax), %ymm1, %ymm2
	vpermi2b	0x10(%eax), %ymm4, %ymm5{%k1}
	vpermi2b	0x12345(%eax), %ymm4, %ymm3{%k2}{z}
	vpermi2b	(%eax,%ebx,4), %ymm1, %ymm2
	vpermi2b	0x14(%eax,%ecx,8), %ymm4, %ymm5{%k1}

	vpermi2b	%zmm0, %zmm1, %zmm2
	vpermi2b	%zmm7, %zmm4, %zmm5{%k1}
	vpermi2b	%zmm2, %zmm4, %zmm3{%k2}{z}
	vpermi2b	(%eax), %zmm1, %zmm2
	vpermi2b	0x10(%eax), %zmm4, %zmm5{%k1}
	vpermi2b	0x12345(%eax), %zmm4, %zmm3{%k2}{z}
	vpermi2b	(%eax,%ebx,4), %zmm1, %zmm2
	vpermi2b	0x14(%eax,%ecx,8), %zmm4, %zmm5{%k1}

	vpermi2w	%xmm0, %xmm1, %xmm2
	vpermi2w	%xmm7, %xmm4, %xmm5{%k1}
	vpermi2w	%xmm2, %xmm4, %xmm3{%k2}{z}
	vpermi2w	(%eax), %xmm1, %xmm2
	vpermi2w	0x10(%eax), %xmm4, %xmm5{%k1}
	vpermi2w	0x12345(%eax), %xmm4, %xmm3{%k2}{z}
	vpermi2w	(%eax,%ebx,4), %xmm1, %xmm2
	vpermi2w	0x14(%eax,%ecx,8), %xmm4, %xmm5{%k1}

	vpermi2w	%ymm0, %ymm1, %ymm2
	vpermi2w	%ymm7, %ymm4, %ymm5{%k1}
	vpermi2w	%ymm2, %ymm4, %ymm3{%k2}{z}
	vpermi2w	(%eax), %ymm1, %ymm2
	vpermi2w	0x10(%eax), %ymm4, %ymm5{%k1}
	vpermi2w	0x12345(%eax), %ymm4, %ymm3{%k2}{z}
	vpermi2w	(%eax,%ebx,4), %ymm1, %ymm2
	vpermi2w	0x14(%eax,%ecx,8), %ymm4, %ymm5{%k1}

	vpermi2w	%zmm0, %zmm1, %zmm2
	vpermi2w	%zmm7, %zmm4, %zmm5{%k1}
	vpermi2w	%zmm2, %zmm4, %zmm3{%k2}{z}
	vpermi2w	(%eax), %zmm1, %zmm2
	vpermi2w	0x10(%eax), %zmm4, %zmm5{%k1}
	vpermi2w	0x12345(%eax), %zmm4, %zmm3{%k2}{z}
	vpermi2w	(%eax,%ebx,4), %zmm1, %zmm2
	vpermi2w	0x14(%eax,%ecx,8), %zmm4, %zmm5{%k1}

	vpermi2d	%xmm0, %xmm1, %xmm2
	vpermi2d	%xmm7, %xmm4, %xmm5{%k1}
	vpermi2d	%xmm2, %xmm4, %xmm3{%k2}{z}
	vpermi2d	(%eax), %xmm1, %xmm2
	vpermi2d	0x10(%eax), %xmm4, %xmm5{%k1}
	vpermi2d	0x12345(%eax), %xmm4, %xmm3{%k2}{z}
	vpermi2d	(%eax,%ebx,4), %xmm1, %xmm2
	vpermi2d	0x14(%eax,%ecx,8), %xmm4, %xmm5{%k1}
	vpermi2d	(%edx){1to4}, %xmm4, %xmm5
	vpermi2d	0x73(%edx){1to4}, %xmm4, %xmm5{%k4}
	vpermi2d	-0x8(%edx){1to4}, %xmm0, %xmm1{%k4}{z}

	vpermi2d	%ymm0, %ymm1, %ymm2
	vpermi2d	%ymm7, %ymm4, %ymm5{%k1}
	vpermi2d	%ymm2, %ymm4, %ymm3{%k2}{z}
	vpermi2d	(%eax), %ymm1, %ymm2
	vpermi2d	0x10(%eax), %ymm4, %ymm5{%k1}
	vpermi2d	0x12345(%eax), %ymm4, %ymm3{%k2}{z}
	vpermi2d	(%eax,%ebx,4), %ymm1, %ymm2
	vpermi2d	0x14(%eax,%ecx,8), %ymm4, %ymm5{%k1}
	vpermi2d	(%edx){1to8}, %ymm4, %ymm5
	vpermi2d	0x73(%edx){1to8}, %ymm4, %ymm5{%k4}
	vpermi2d	-0x8(%edx){1to8}, %ymm0, %ymm1{%k4}{z}

	vpermi2d	%zmm0, %zmm1, %zmm2
	vpermi2d	%zmm7, %zmm4, %zmm5{%k1}
	vpermi2d	%zmm2, %zmm4, %zmm3{%k2}{z}
	vpermi2d	(%eax), %zmm1, %zmm2
	vpermi2d	0x10(%eax), %zmm4, %zmm5{%k1}
	vpermi2d	0x12345(%eax), %zmm4, %zmm3{%k2}{z}
	vpermi2d	(%eax,%ebx,4), %zmm1, %zmm2
	vpermi2d	0x14(%eax,%ecx,8), %zmm4, %zmm5{%k1}
	vpermi2d	(%edx){1to16}, %zmm4, %zmm5
	vpermi2d	0x73(%edx){1to16}, %zmm4, %zmm5{%k4}
	vpermi2d	-0x8(%edx){1to16}, %zmm0, %zmm1{%k4}{z}

	vpermi2q	%xmm0, %xmm1, %xmm2
	vpermi2q	%xmm7, %xmm4, %xmm5{%k1}
	vpermi2q	%xmm2, %xmm4, %xmm3{%k2}{z}
	vpermi2q	(%eax), %xmm1, %xmm2
	vpermi2q	0x10(%eax), %xmm4, %xmm5{%k1}
	vpermi2q	0x12345(%eax), %xmm4, %xmm3{%k2}{z}
	vpermi2q	(%eax,%ebx,4), %xmm1, %xmm2
	vpermi2q	0x14(%eax,%ecx,8), %xmm4, %xmm5{%k1}
	vpermi2q	(%edx){1to2}, %xmm4, %xmm5
	vpermi2q	0x73(%edx){1to2}, %xmm4, %xmm5{%k4}
	vpermi2q	-0x8(%edx){1to2}, %xmm0, %xmm1{%k4}{z}

	vpermi2q	%ymm0, %ymm1, %ymm2
	vpermi2q	%ymm7, %ymm4, %ymm5{%k1}
	vpermi2q	%ymm2, %ymm4, %ymm3{%k2}{z}
	vpermi2q	(%eax), %ymm1, %ymm2
	vpermi2q	0x10(%eax), %ymm4, %ymm5{%k1}
	vpermi2q	0x12345(%eax), %ymm4, %ymm3{%k2}{z}
	vpermi2q	(%eax,%ebx,4), %ymm1, %ymm2
	vpermi2q	0x14(%eax,%ecx,8), %ymm4, %ymm5{%k1}
	vpermi2q	(%edx){1to4}, %ymm4, %ymm5
	vpermi2q	0x73(%edx){1to4}, %ymm4, %ymm5{%k4}
	vpermi2q	-0x8(%edx){1to4}, %ymm0, %ymm1{%k4}{z}

	vpermi2q	%zmm0, %zmm1, %zmm2
	vpermi2q	%zmm7, %zmm4, %zmm5{%k1}
	vpermi2q	%zmm2, %zmm4, %zmm3{%k2}{z}
	vpermi2q	(%eax), %zmm1, %zmm2
	vpermi2q	0x10(%eax), %zmm4, %zmm5{%k1}
	vpermi2q	0x12345(%eax), %zmm4, %zmm3{%k2}{z}
	vpermi2q	(%eax,%ebx,4), %zmm1, %zmm2
	vpermi2q	0x14(%eax,%ecx,8), %zmm4, %zmm5{%k1}
	vpermi2q	(%edx){1to8}, %zmm4, %zmm5
	vpermi2q	0x73(%edx){1to8}, %zmm4, %zmm5{%k4}
	vpermi2q	-0x8(%edx){1to8}, %zmm0, %zmm1{%k4}{z}

	vpermt2b	%xmm0, %xmm1, %xmm2
	vpermt2b	%xmm7, %xmm4, %xmm5{%k1}
	vpermt2b	%xmm2, %xmm4, %xmm3{%k2}{z}
	vpermt2b	(%eax), %xmm1, %xmm2
	vpermt2b	0x10(%eax), %xmm4, %xmm5{%k1}
	vpermt2b	0x12345(%eax), %xmm4, %xmm3{%k2}{z}
	vpermt2b	(%eax,%ebx,4), %xmm1, %xmm2
	vpermt2b	0x14(%eax,%ecx,8), %xmm4, %xmm5{%k1}

	vpermt2b	%ymm0, %ymm1, %ymm2
	vpermt2b	%ymm7, %ymm4, %ymm5{%k1}
	vpermt2b	%ymm2, %ymm4, %ymm3{%k2}{z}
	vpermt2b	(%eax), %ymm1, %ymm2
	vpermt2b	0x10(%eax), %ymm4, %ymm5{%k1}
	vpermt2b	0x12345(%eax), %ymm4, %ymm3{%k2}{z}
	vpermt2b	(%eax,%ebx,4), %ymm1, %ymm2
	vpermt2b	0x14(%eax,%ecx,8), %ymm4, %ymm5{%k1}

	vpermt2b	%zmm0, %zmm1, %zmm2
	vpermt2b	%zmm7, %zmm4, %zmm5{%k1}
	vpermt2b	%zmm2, %zmm4, %zmm3{%k2}{z}
	vpermt2b	(%eax), %zmm1, %zmm2
	vpermt2b	0x10(%eax), %zmm4, %zmm5{%k1}
	vpermt2b	0x12345(%eax), %zmm4, %zmm3{%k2}{z}
	vpermt2b	(%eax,%ebx,4), %zmm1, %zmm2
	vpermt2b	0x14(%eax,%ecx,8), %zmm4, %zmm5{%k1}

	vpermt2w	%xmm0, %xmm1, %xmm2
	vpermt2w	%xmm7, %xmm4, %xmm5{%k1}
	vpermt2w	%xmm2, %xmm4, %xmm3{%k2}{z}
	vpermt2w	(%eax), %xmm1, %xmm2
	vpermt2w	0x10(%eax), %xmm4, %xmm5{%k1}
	vpermt2w	0x12345(%eax), %xmm4, %xmm3{%k2}{z}
	vpermt2w	(%eax,%ebx,4), %xmm1, %xmm2
	vpermt2w	0x14(%eax,%ecx,8), %xmm4, %xmm5{%k1}

	vpermt2w	%ymm0, %ymm1, %ymm2
	vpermt2w	%ymm7, %ymm4, %ymm5{%k1}
	vpermt2w	%ymm2, %ymm4, %ymm3{%k2}{z}
	vpermt2w	(%eax), %ymm1, %ymm2
	vpermt2w	0x10(%eax), %ymm4, %ymm5{%k1}
	vpermt2w	0x12345(%eax), %ymm4, %ymm3{%k2}{z}
	vpermt2w	(%eax,%ebx,4), %ymm1, %ymm2
	vpermt2w	0x14(%eax,%ecx,8), %ymm4, %ymm5{%k1}

	vpermt2w	%zmm0, %zmm1, %zmm2
	vpermt2w	%zmm7, %zmm4, %zmm5{%k1}
	vpermt2w	%zmm2, %zmm4, %zmm3{%k2}{z}
	vpermt2w	(%eax), %zmm1, %zmm2
	vpermt2w	0x10(%eax), %zmm4, %zmm5{%k1}
	vpermt2w	0x12345(%eax), %zmm4, %zmm3{%k2}{z}
	vpermt2w	(%eax,%ebx,4), %zmm1, %zmm2
	vpermt2w	0x14(%eax,%ecx,8), %zmm4, %zmm5{%k1}

	vpermt2d	%xmm0, %xmm1, %xmm2
	vpermt2d	%xmm7, %xmm4, %xmm5{%k1}
	vpermt2d	%xmm2, %xmm4, %xmm3{%k2}{z}
	vpermt2d	(%eax), %xmm1, %xmm2
	vpermt2d	0x10(%eax), %xmm4, %xmm5{%k1}
	vpermt2d	0x12345(%eax), %xmm4, %xmm3{%k2}{z}
	vpermt2d	(%eax,%ebx,4), %xmm1, %xmm2
	vpermt2d	0x14(%eax,%ecx,8), %xmm4, %xmm5{%k1}
	vpermt2d	(%edx){1to4}, %xmm4, %xmm5
	vpermt2d	0x73(%edx){1to4}, %xmm4, %xmm5{%k4}
	vpermt2d	-0x8(%edx){1to4}, %xmm0, %xmm1{%k4}{z}

	vpermt2d	%ymm0, %ymm1, %ymm2
	vpermt2d	%ymm7, %ymm4, %ymm5{%k1}
	vpermt2d	%ymm2, %ymm4, %ymm3{%k2}{z}
	vpermt2d	(%eax), %ymm1, %ymm2
	vpermt2d	0x10(%eax), %ymm4, %ymm5{%k1}
	vpermt2d	0x12345(%eax), %ymm4, %ymm3{%k2}{z}
	vpermt2d	(%eax,%ebx,4), %ymm1, %ymm2
	vpermt2d	0x14(%eax,%ecx,8), %ymm4, %ymm5{%k1}
	vpermt2d	(%edx){1to8}, %ymm4, %ymm5
	vpermt2d	0x73(%edx){1to8}, %ymm4, %ymm5{%k4}
	vpermt2d	-0x8(%edx){1to8}, %ymm0, %ymm1{%k4}{z}

	vpermt2d	%zmm0, %zmm1, %zmm2
	vpermt2d	%zmm7, %zmm4, %zmm5{%k1}
	vpermt2d	%zmm2, %zmm4, %zmm3{%k2}{z}
	vpermt2d	(%eax), %zmm1, %zmm2
	vpermt2d	0x10(%eax), %zmm4, %zmm5{%k1}
	vpermt2d	0x12345(%eax), %zmm4, %zmm3{%k2}{z}
	vpermt2d	(%eax,%ebx,4), %zmm1, %zmm2
	vpermt2d	0x14(%eax,%ecx,8), %zmm4, %zmm5{%k1}
	vpermt2d	(%edx){1to16}, %zmm4, %zmm5
	vpermt2d	0x73(%edx){1to16}, %zmm4, %zmm5{%k4}
	vpermt2d	-0x8(%edx){1to16}, %zmm0, %zmm1{%k4}{z}

	vpermt2q	%xmm0, %xmm1, %xmm2
	vpermt2q	%xmm7, %xmm4, %xmm5{%k1}
	vpermt2q	%xmm2, %xmm4, %xmm3{%k2}{z}
	vpermt2q	(%eax), %xmm1, %xmm2
	vpermt2q	0x10(%eax), %xmm4, %xmm5{%k1}
	vpermt2q	0x12345(%eax), %xmm4, %xmm3{%k2}{z}
	vpermt2q	(%eax,%ebx,4), %xmm1, %xmm2
	vpermt2q	0x14(%eax,%ecx,8), %xmm4, %xmm5{%k1}
	vpermt2q	(%edx){1to2}, %xmm4, %xmm5
	vpermt2q	0x73(%edx){1to2}, %xmm4, %xmm5{%k4}
	vpermt2q	-0x8(%edx){1to2}, %xmm0, %xmm1{%k4}{z}

	vpermt2q	%ymm0, %ymm1, %ymm2
	vpermt2q	%ymm7, %ymm4, %ymm5{%k1}
	vpermt2q	%ymm2, %ymm4, %ymm3{%k2}{z}
	vpermt2q	(%eax), %ymm1, %ymm2
	vpermt2q	0x10(%eax), %ymm4, %ymm5{%k1}
	vpermt2q	0x12345(%eax), %ymm4, %ymm3{%k2}{z}
	vpermt2q	(%eax,%ebx,4), %ymm1, %ymm2
	vpermt2q	0x14(%eax,%ecx,8), %ymm4, %ymm5{%k1}
	vpermt2q	(%edx){1to4}, %ymm4, %ymm5
	vpermt2q	0x73(%edx){1to4}, %ymm4, %ymm5{%k4}
	vpermt2q	-0x8(%edx){1to4}, %ymm0, %ymm1{%k4}{z}

	vpermt2q	%zmm0, %zmm1, %zmm2
	vpermt2q	%zmm7, %zmm4, %zmm5{%k1}
	vpermt2q	%zmm2, %zmm4, %zmm3{%k2}{z}
	vpermt2q	(%eax), %zmm1, %zmm2
	vpermt2q	0x10(%eax), %zmm4, %zmm5{%k1}
	vpermt2q	0x12345(%eax), %zmm4, %zmm3{%k2}{z}
	vpermt2q	(%eax,%ebx,4), %zmm1, %zmm2
	vpermt2q	0x14(%eax,%ecx,8), %zmm4, %zmm5{%k1}
	vpermt2q	(%edx){1to8}, %zmm4, %zmm5
	vpermt2q	0x73(%edx){1to8}, %zmm4, %zmm5{%k4}
	vpermt2q	-0x8(%edx){1to8}, %zmm0, %zmm1{%k4}{z}

	vpmultishiftqb	%xmm0, %xmm1, %xmm2
	vpmultishiftqb	%xmm7, %xmm4, %xmm5{%k1}
	vpmultishiftqb	%xmm2, %xmm4, %xmm3{%k2}{z}
	vpmultishiftqb	(%eax), %xmm1, %xmm2
	vpmultishiftqb	0x10(%eax), %xmm4, %xmm5{%k1}
	vpmultishiftqb	0x12345(%eax), %xmm4, %xmm3{%k2}{z}
	vpmultishiftqb	(%eax,%ebx,4), %xmm1, %xmm2
	vpmultishiftqb	0x14(%eax,%ecx,8), %xmm4, %xmm5{%k1}
	vpmultishiftqb	(%edx){1to2}, %xmm4, %xmm5
	vpmultishiftqb	0x73(%edx){1to2}, %xmm4, %xmm5{%k4}
	vpmultishiftqb	-0x8(%edx){1to2}, %xmm0, %xmm1{%k4}{z}

	vpmultishiftqb	%ymm0, %ymm1, %ymm2
	vpmultishiftqb	%ymm7, %ymm4, %ymm5{%k1}
	vpmultishiftqb	%ymm2, %ymm4, %ymm3{%k2}{z}
	vpmultishiftqb	(%eax), %ymm1, %ymm2
	vpmultishiftqb	0x10(%eax), %ymm4, %ymm5{%k1}
	vpmultishiftqb	0x12345(%eax), %ymm4, %ymm3{%k2}{z}
	vpmultishiftqb	(%eax,%ebx,4), %ymm1, %ymm2
	vpmultishiftqb	0x14(%eax,%ecx,8), %ymm4, %ymm5{%k1}
	vpmultishiftqb	(%edx){1to4}, %ymm4, %ymm5
	vpmultishiftqb	0x73(%edx){1to4}, %ymm4, %ymm5{%k4}
	vpmultishiftqb	-0x8(%edx){1to4}, %ymm0, %ymm1{%k4}{z}

	vpmultishiftqb	%zmm0, %zmm1, %zmm2
	vpmultishiftqb	%zmm7, %zmm4, %zmm5{%k1}
	vpmultishiftqb	%zmm2, %zmm4, %zmm3{%k2}{z}
	vpmultishiftqb	(%eax), %zmm1, %zmm2
	vpmultishiftqb	0x10(%eax), %zmm4, %zmm5{%k1}
	vpmultishiftqb	0x12345(%eax), %zmm4, %zmm3{%k2}{z}
	vpmultishiftqb	(%eax,%ebx,4), %zmm1, %zmm2
	vpmultishiftqb	0x14(%eax,%ecx,8), %zmm4, %zmm5{%k1}
	vpmultishiftqb	(%edx){1to8}, %zmm4, %zmm5
	vpmultishiftqb	0x73(%edx){1to8}, %zmm4, %zmm5{%k4}
	vpmultishiftqb	-0x8(%edx){1to8}, %zmm0, %zmm1{%k4}{z}
.size libdis_test, [.-libdis_test]
