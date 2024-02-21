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
	vpopcntb	%xmm0, %xmm7
	vpopcntb	(%edi), %xmm7
	vpopcntb	0x64(%edx), %xmm6
	vpopcntb	0x64(%edi,%ebx,4), %xmm1
	vpopcntb	%xmm4, %xmm5{%k2}
	vpopcntb	%xmm6, %xmm7{%k3}{z}
	vpopcntb	0x7777(%eax), %xmm7{%k4}
	vpopcntb	0x6666(%eax), %xmm0{%k5}{z}

	vpopcntb	%ymm0, %ymm7
	vpopcntb	(%edi), %ymm7
	vpopcntb	0x64(%edx), %ymm6
	vpopcntb	0x64(%edi,%ebx,4), %ymm1
	vpopcntb	%ymm4, %ymm5{%k2}
	vpopcntb	%ymm6, %ymm7{%k3}{z}
	vpopcntb	0x7777(%eax), %ymm7{%k4}
	vpopcntb	0x6666(%eax), %ymm0{%k5}{z}

	vpopcntb	%zmm0, %zmm7
	vpopcntb	(%edi), %zmm7
	vpopcntb	0x64(%edx), %zmm6
	vpopcntb	0x64(%edi,%ebx,4), %zmm1
	vpopcntb	%zmm4, %zmm5{%k2}
	vpopcntb	%zmm6, %zmm7{%k3}{z}
	vpopcntb	0x7777(%eax), %zmm7{%k4}
	vpopcntb	0x6666(%eax), %zmm0{%k5}{z}

	vpopcntw	%xmm0, %xmm7
	vpopcntw	(%edi), %xmm7
	vpopcntw	0x64(%edx), %xmm6
	vpopcntw	0x64(%edi,%ebx,4), %xmm1
	vpopcntw	%xmm4, %xmm5{%k2}
	vpopcntw	%xmm6, %xmm7{%k3}{z}
	vpopcntw	0x7777(%eax), %xmm7{%k4}
	vpopcntw	0x6666(%eax), %xmm0{%k5}{z}

	vpopcntw	%ymm0, %ymm7
	vpopcntw	(%edi), %ymm7
	vpopcntw	0x64(%edx), %ymm6
	vpopcntw	0x64(%edi,%ebx,4), %ymm1
	vpopcntw	%ymm4, %ymm5{%k2}
	vpopcntw	%ymm6, %ymm7{%k3}{z}
	vpopcntw	0x7777(%eax), %ymm7{%k4}
	vpopcntw	0x6666(%eax), %ymm0{%k5}{z}

	vpopcntw	%zmm0, %zmm7
	vpopcntw	(%edi), %zmm7
	vpopcntw	0x64(%edx), %zmm6
	vpopcntw	0x64(%edi,%ebx,4), %zmm1
	vpopcntw	%zmm4, %zmm5{%k2}
	vpopcntw	%zmm6, %zmm7{%k3}{z}
	vpopcntw	0x7777(%eax), %zmm7{%k4}
	vpopcntw	0x6666(%eax), %zmm0{%k5}{z}

	vpopcntd	%xmm0, %xmm7
	vpopcntd	(%edi), %xmm7
	vpopcntd	0x64(%edx), %xmm6
	vpopcntd	0x64(%edi,%ebx,4), %xmm1
	vpopcntd	%xmm4, %xmm5{%k2}
	vpopcntd	%xmm6, %xmm7{%k3}{z}
	vpopcntd	0x7777(%eax), %xmm7{%k4}
	vpopcntd	0x6666(%eax), %xmm0{%k5}{z}
	vpopcntd	(%ecx){1to4}, %xmm7
	vpopcntd	0x12345(%ecx){1to4}, %xmm7

	vpopcntd	%ymm0, %ymm7
	vpopcntd	(%edi), %ymm7
	vpopcntd	0x64(%edx), %ymm6
	vpopcntd	0x64(%edi,%ebx,4), %ymm1
	vpopcntd	%ymm4, %ymm5{%k2}
	vpopcntd	%ymm6, %ymm7{%k3}{z}
	vpopcntd	0x7777(%eax), %ymm7{%k4}
	vpopcntd	0x6666(%eax), %ymm0{%k5}{z}
	vpopcntd	(%ecx){1to8}, %ymm7
	vpopcntd	0x54321(%ecx){1to8}, %ymm7

	vpopcntd	%zmm0, %zmm7
	vpopcntd	(%edi), %zmm7
	vpopcntd	0x64(%edx), %zmm6
	vpopcntd	0x64(%edi,%ebx,4), %zmm1
	vpopcntd	%zmm4, %zmm5{%k2}
	vpopcntd	%zmm6, %zmm7{%k3}{z}
	vpopcntd	0x7777(%eax), %zmm7{%k4}
	vpopcntd	0x6666(%eax), %zmm0{%k5}{z}
	vpopcntd	(%ecx){1to16}, %zmm7
	vpopcntd	0x34543(%ecx){1to16}, %zmm7

	vpopcntq	%xmm0, %xmm7
	vpopcntq	(%edi), %xmm7
	vpopcntq	0x64(%edx), %xmm6
	vpopcntq	0x64(%edi,%ebx,4), %xmm1
	vpopcntq	%xmm4, %xmm5{%k2}
	vpopcntq	%xmm6, %xmm7{%k3}{z}
	vpopcntq	0x7777(%eax), %xmm7{%k4}
	vpopcntq	0x6666(%eax), %xmm0{%k5}{z}
	vpopcntq	(%ecx){1to2}, %xmm7
	vpopcntq	0x12345(%ecx){1to2}, %xmm7

	vpopcntq	%ymm0, %ymm7
	vpopcntq	(%edi), %ymm7
	vpopcntq	0x64(%edx), %ymm6
	vpopcntq	0x64(%edi,%ebx,4), %ymm1
	vpopcntq	%ymm4, %ymm5{%k2}
	vpopcntq	%ymm6, %ymm7{%k3}{z}
	vpopcntq	0x7777(%eax), %ymm7{%k4}
	vpopcntq	0x6666(%eax), %ymm0{%k5}{z}
	vpopcntq	(%ecx){1to4}, %ymm7
	vpopcntq	0x54321(%ecx){1to4}, %ymm7

	vpopcntq	%zmm0, %zmm7
	vpopcntq	(%edi), %zmm7
	vpopcntq	0x64(%edx), %zmm6
	vpopcntq	0x64(%edi,%ebx,4), %zmm1
	vpopcntq	%zmm4, %zmm5{%k2}
	vpopcntq	%zmm6, %zmm7{%k3}{z}
	vpopcntq	0x7777(%eax), %zmm7{%k4}
	vpopcntq	0x6666(%eax), %zmm0{%k5}{z}
	vpopcntq	(%ecx){1to8}, %zmm7
	vpopcntq	0x34543(%ecx){1to8}, %zmm7

	vpshufbitqmb	%xmm1, %xmm2, %k3
	vpshufbitqmb	%xmm3, %xmm4, %k4{%k5}
	vpshufbitqmb	(%edi), %xmm7, %k0
	vpshufbitqmb	(%edi), %xmm7, %k0{%k1}
	vpshufbitqmb	0x167(%edi), %xmm7, %k0
	vpshufbitqmb	0x761(%edi), %xmm7, %k0{%k1}
	vpshufbitqmb	0x167(%edi, %esi, 4), %xmm7, %k0
	vpshufbitqmb	0x761(%edi, %edx, 8), %xmm7, %k0{%k1}

	vpshufbitqmb	%ymm1, %ymm2, %k3
	vpshufbitqmb	%ymm3, %ymm4, %k4{%k5}
	vpshufbitqmb	(%edi), %ymm7, %k0
	vpshufbitqmb	(%edi), %ymm7, %k0{%k1}
	vpshufbitqmb	0x167(%edi), %ymm7, %k0
	vpshufbitqmb	0x761(%edi), %ymm7, %k0{%k1}
	vpshufbitqmb	0x167(%edi, %esi, 4), %ymm7, %k0
	vpshufbitqmb	0x761(%edi, %edx, 8), %ymm7, %k0{%k1}

	vpshufbitqmb	%zmm1, %zmm2, %k3
	vpshufbitqmb	%zmm3, %zmm4, %k4{%k5}
	vpshufbitqmb	(%edi), %zmm7, %k0
	vpshufbitqmb	(%edi), %zmm7, %k0{%k1}
	vpshufbitqmb	0x167(%edi), %zmm7, %k0
	vpshufbitqmb	0x761(%edi), %zmm7, %k0{%k1}
	vpshufbitqmb	0x167(%edi, %esi, 4), %zmm7, %k0
	vpshufbitqmb	0x761(%edi, %edx, 8), %zmm7, %k0{%k1}
.size libdis_test, [.-libdis_test]
