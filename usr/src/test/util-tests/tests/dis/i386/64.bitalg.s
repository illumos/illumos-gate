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
 * AVX512 bit algorithms (BITALG) and vpopcntdq.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	vpopcntb	%xmm20, %xmm21
	vpopcntb	(%r10), %xmm22
	vpopcntb	0x64(%r9), %xmm23
	vpopcntb	0x64(%r10,%r11,4), %xmm19
	vpopcntb	%xmm24, %xmm25{%k2}
	vpopcntb	%xmm26, %xmm27{%k3}{z}
	vpopcntb	0x7777(%rax), %xmm28{%k4}
	vpopcntb	0x6666(%rax), %xmm29{%k5}{z}

	vpopcntb	%ymm20, %ymm21
	vpopcntb	(%r10), %ymm22
	vpopcntb	0x64(%r9), %ymm23
	vpopcntb	0x64(%r10,%r11,4), %ymm19
	vpopcntb	%ymm24, %ymm25{%k2}
	vpopcntb	%ymm26, %ymm27{%k3}{z}
	vpopcntb	0x7777(%rax), %ymm28{%k4}
	vpopcntb	0x6666(%rax), %ymm29{%k5}{z}

	vpopcntb	%zmm20, %zmm21
	vpopcntb	(%r10), %zmm22
	vpopcntb	0x64(%r9), %zmm23
	vpopcntb	0x64(%r10,%r11,4), %zmm19
	vpopcntb	%zmm24, %zmm25{%k2}
	vpopcntb	%zmm26, %zmm27{%k3}{z}
	vpopcntb	0x7777(%rax), %zmm28{%k4}
	vpopcntb	0x6666(%rax), %zmm29{%k5}{z}

	vpopcntw	%xmm20, %xmm21
	vpopcntw	(%r10), %xmm22
	vpopcntw	0x64(%r9), %xmm23
	vpopcntw	0x64(%r10,%r11,4), %xmm19
	vpopcntw	%xmm24, %xmm25{%k2}
	vpopcntw	%xmm26, %xmm27{%k3}{z}
	vpopcntw	0x7777(%rax), %xmm28{%k4}
	vpopcntw	0x6666(%rax), %xmm29{%k5}{z}

	vpopcntw	%ymm20, %ymm21
	vpopcntw	(%r10), %ymm22
	vpopcntw	0x64(%r9), %ymm23
	vpopcntw	0x64(%r10,%r11,4), %ymm19
	vpopcntw	%ymm24, %ymm25{%k2}
	vpopcntw	%ymm26, %ymm27{%k3}{z}
	vpopcntw	0x7777(%rax), %ymm28{%k4}
	vpopcntw	0x6666(%rax), %ymm29{%k5}{z}

	vpopcntw	%zmm20, %zmm21
	vpopcntw	(%r10), %zmm22
	vpopcntw	0x64(%r9), %zmm23
	vpopcntw	0x64(%r10,%r11,4), %zmm19
	vpopcntw	%zmm24, %zmm25{%k2}
	vpopcntw	%zmm26, %zmm27{%k3}{z}
	vpopcntw	0x7777(%rax), %zmm28{%k4}
	vpopcntw	0x6666(%rax), %zmm29{%k5}{z}

	vpopcntd	%xmm20, %xmm21
	vpopcntd	(%r10), %xmm22
	vpopcntd	0x64(%r9), %xmm23
	vpopcntd	0x64(%r10,%r11,4), %xmm19
	vpopcntd	%xmm24, %xmm25{%k2}
	vpopcntd	%xmm26, %xmm27{%k3}{z}
	vpopcntd	0x7777(%rax), %xmm28{%k4}
	vpopcntd	0x6666(%rax), %xmm29{%k5}{z}
	vpopcntd	(%rcx){1to4}, %xmm7
	vpopcntd	0x12345(%rcx){1to4}, %xmm7

	vpopcntd	%ymm20, %ymm21
	vpopcntd	(%r10), %ymm22
	vpopcntd	0x64(%r9), %ymm23
	vpopcntd	0x64(%r10,%r11,4), %ymm19
	vpopcntd	%ymm24, %ymm25{%k2}
	vpopcntd	%ymm26, %ymm27{%k3}{z}
	vpopcntd	0x7777(%rax), %ymm28{%k4}
	vpopcntd	0x6666(%rax), %ymm29{%k5}{z}
	vpopcntd	(%rcx){1to8}, %ymm7
	vpopcntd	0x54321(%rcx){1to8}, %ymm7

	vpopcntd	%zmm20, %zmm21
	vpopcntd	(%r10), %zmm22
	vpopcntd	0x64(%r9), %zmm23
	vpopcntd	0x64(%r10,%r11,4), %zmm19
	vpopcntd	%zmm24, %zmm25{%k2}
	vpopcntd	%zmm26, %zmm27{%k3}{z}
	vpopcntd	0x7777(%rax), %zmm28{%k4}
	vpopcntd	0x6666(%rax), %zmm29{%k5}{z}
	vpopcntd	(%rcx){1to16}, %zmm7
	vpopcntd	0x34543(%rcx){1to16}, %zmm7

	vpopcntq	%xmm20, %xmm21
	vpopcntq	(%r10), %xmm22
	vpopcntq	0x64(%r9), %xmm23
	vpopcntq	0x64(%r10,%r11,4), %xmm19
	vpopcntq	%xmm24, %xmm25{%k2}
	vpopcntq	%xmm26, %xmm27{%k3}{z}
	vpopcntq	0x7777(%rax), %xmm28{%k4}
	vpopcntq	0x6666(%rax), %xmm29{%k5}{z}
	vpopcntq	(%rcx){1to2}, %xmm7
	vpopcntq	0x12345(%rcx){1to2}, %xmm7

	vpopcntq	%ymm20, %ymm21
	vpopcntq	(%r10), %ymm22
	vpopcntq	0x64(%r9), %ymm23
	vpopcntq	0x64(%r10,%r11,4), %ymm19
	vpopcntq	%ymm24, %ymm25{%k2}
	vpopcntq	%ymm26, %ymm27{%k3}{z}
	vpopcntq	0x7777(%rax), %ymm28{%k4}
	vpopcntq	0x6666(%rax), %ymm29{%k5}{z}
	vpopcntq	(%rcx){1to4}, %ymm7
	vpopcntq	0x54321(%rcx){1to4}, %ymm7

	vpopcntq	%zmm20, %zmm21
	vpopcntq	(%r10), %zmm22
	vpopcntq	0x64(%r9), %zmm23
	vpopcntq	0x64(%r10,%r11,4), %zmm19
	vpopcntq	%zmm24, %zmm25{%k2}
	vpopcntq	%zmm26, %zmm27{%k3}{z}
	vpopcntq	0x7777(%rax), %zmm28{%k4}
	vpopcntq	0x6666(%rax), %zmm29{%k5}{z}
	vpopcntq	(%rcx){1to8}, %zmm7
	vpopcntq	0x34543(%rcx){1to8}, %zmm7

	vpshufbitqmb	%xmm1, %xmm2, %k3
	vpshufbitqmb	%xmm11, %xmm12, %k4{%k5}
	vpshufbitqmb	(%r10), %xmm22, %k0
	vpshufbitqmb	(%r10), %xmm22, %k0{%k1}
	vpshufbitqmb	0x167(%r10), %xmm22, %k0
	vpshufbitqmb	0x761(%r10), %xmm22, %k0{%k1}
	vpshufbitqmb	0x167(%r10, %r8, 4), %xmm22, %k0
	vpshufbitqmb	0x761(%r10, %r9, 8), %xmm22, %k0{%k1}

	vpshufbitqmb	%ymm1, %ymm2, %k3
	vpshufbitqmb	%ymm11, %ymm12, %k4{%k5}
	vpshufbitqmb	(%r10), %ymm22, %k0
	vpshufbitqmb	(%r10), %ymm22, %k0{%k1}
	vpshufbitqmb	0x167(%r10), %ymm22, %k0
	vpshufbitqmb	0x761(%r10), %ymm22, %k0{%k1}
	vpshufbitqmb	0x167(%r10, %r8, 4), %ymm22, %k0
	vpshufbitqmb	0x761(%r10, %r9, 8), %ymm22, %k0{%k1}

	vpshufbitqmb	%zmm1, %zmm2, %k3
	vpshufbitqmb	%zmm11, %zmm12, %k4{%k5}
	vpshufbitqmb	(%r10), %zmm22, %k0
	vpshufbitqmb	(%r10), %zmm22, %k0{%k1}
	vpshufbitqmb	0x167(%r10), %zmm22, %k0
	vpshufbitqmb	0x761(%r10), %zmm22, %k0{%k1}
	vpshufbitqmb	0x167(%r10, %r8, 4), %zmm22, %k0
	vpshufbitqmb	0x761(%r10, %r9, 8), %zmm22, %k0{%k1}
.size libdis_test, [.-libdis_test]
