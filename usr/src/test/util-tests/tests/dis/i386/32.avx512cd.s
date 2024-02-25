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
 * AVX-512 CD (Conflict Detection) instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	vpconflictd	%xmm0, %xmm1
	vpconflictd	%xmm2, %xmm3{%k1}
	vpconflictd	%xmm4, %xmm5{%k2}{z}
	vpconflictd	(%eax), %xmm6
	vpconflictd	0x167(%eax), %xmm6{%k3}
	vpconflictd	-0x23(%eax,%ebx,4), %xmm7{%k4}
	vpconflictd	(%ecx){1to4}, %xmm5
	vpconflictd	0x10(%edx){1to4}, %xmm3{%k5}
	vpconflictd	0x88(%ecx){1to4}, %xmm3{%k5}{z}

	vpconflictd	%ymm0, %ymm1
	vpconflictd	%ymm2, %ymm3{%k1}
	vpconflictd	%ymm4, %ymm5{%k2}{z}
	vpconflictd	(%eax), %ymm6
	vpconflictd	0x167(%eax), %ymm6{%k3}
	vpconflictd	-0x23(%eax,%ebx,4), %ymm7{%k4}
	vpconflictd	(%ecx){1to8}, %ymm5
	vpconflictd	0x10(%edx){1to8}, %ymm3{%k5}
	vpconflictd	0x88(%ecx){1to8}, %ymm3{%k5}{z}

	vpconflictd	%zmm0, %zmm1
	vpconflictd	%zmm2, %zmm3{%k1}
	vpconflictd	%zmm4, %zmm5{%k2}{z}
	vpconflictd	(%eax), %zmm6
	vpconflictd	0x167(%eax), %zmm6{%k3}
	vpconflictd	-0x23(%eax,%ebx,4), %zmm7{%k4}
	vpconflictd	(%ecx){1to16}, %zmm5
	vpconflictd	0x10(%edx){1to16}, %zmm3{%k5}
	vpconflictd	0x88(%ecx){1to16}, %zmm3{%k5}{z}

	vpconflictq	%xmm0, %xmm1
	vpconflictq	%xmm2, %xmm3{%k1}
	vpconflictq	%xmm4, %xmm5{%k2}{z}
	vpconflictq	(%eax), %xmm6
	vpconflictq	0x167(%eax), %xmm6{%k3}
	vpconflictq	-0x23(%eax,%ebx,4), %xmm7{%k4}
	vpconflictq	(%ecx){1to2}, %xmm5
	vpconflictq	0x10(%edx){1to2}, %xmm3{%k5}
	vpconflictq	0x88(%ecx){1to2}, %xmm3{%k5}{z}

	vpconflictq	%ymm0, %ymm1
	vpconflictq	%ymm2, %ymm3{%k1}
	vpconflictq	%ymm4, %ymm5{%k2}{z}
	vpconflictq	(%eax), %ymm6
	vpconflictq	0x167(%eax), %ymm6{%k3}
	vpconflictq	-0x23(%eax,%ebx,4), %ymm7{%k4}
	vpconflictq	(%ecx){1to4}, %ymm5
	vpconflictq	0x10(%edx){1to4}, %ymm3{%k5}
	vpconflictq	0x88(%ecx){1to4}, %ymm3{%k5}{z}

	vpconflictq	%zmm0, %zmm1
	vpconflictq	%zmm2, %zmm3{%k1}
	vpconflictq	%zmm4, %zmm5{%k2}{z}
	vpconflictq	(%eax), %zmm6
	vpconflictq	0x167(%eax), %zmm6{%k3}
	vpconflictq	-0x23(%eax,%ebx,4), %zmm7{%k4}
	vpconflictq	(%ecx){1to8}, %zmm5
	vpconflictq	0x10(%edx){1to8}, %zmm3{%k5}
	vpconflictq	0x88(%ecx){1to8}, %zmm3{%k5}{z}

	vplzcntd	%xmm0, %xmm1
	vplzcntd	%xmm2, %xmm3{%k1}
	vplzcntd	%xmm4, %xmm5{%k2}{z}
	vplzcntd	(%eax), %xmm6
	vplzcntd	0x167(%eax), %xmm6{%k3}
	vplzcntd	-0x23(%eax,%ebx,4), %xmm7{%k4}
	vplzcntd	(%ecx){1to4}, %xmm5
	vplzcntd	0x10(%edx){1to4}, %xmm3{%k5}
	vplzcntd	0x88(%ecx){1to4}, %xmm3{%k5}{z}

	vplzcntd	%ymm0, %ymm1
	vplzcntd	%ymm2, %ymm3{%k1}
	vplzcntd	%ymm4, %ymm5{%k2}{z}
	vplzcntd	(%eax), %ymm6
	vplzcntd	0x167(%eax), %ymm6{%k3}
	vplzcntd	-0x23(%eax,%ebx,4), %ymm7{%k4}
	vplzcntd	(%ecx){1to8}, %ymm5
	vplzcntd	0x10(%edx){1to8}, %ymm3{%k5}
	vplzcntd	0x88(%ecx){1to8}, %ymm3{%k5}{z}

	vplzcntd	%zmm0, %zmm1
	vplzcntd	%zmm2, %zmm3{%k1}
	vplzcntd	%zmm4, %zmm5{%k2}{z}
	vplzcntd	(%eax), %zmm6
	vplzcntd	0x167(%eax), %zmm6{%k3}
	vplzcntd	-0x23(%eax,%ebx,4), %zmm7{%k4}
	vplzcntd	(%ecx){1to16}, %zmm5
	vplzcntd	0x10(%edx){1to16}, %zmm3{%k5}
	vplzcntd	0x88(%ecx){1to16}, %zmm3{%k5}{z}

	vplzcntq	%xmm0, %xmm1
	vplzcntq	%xmm2, %xmm3{%k1}
	vplzcntq	%xmm4, %xmm5{%k2}{z}
	vplzcntq	(%eax), %xmm6
	vplzcntq	0x167(%eax), %xmm6{%k3}
	vplzcntq	-0x23(%eax,%ebx,4), %xmm7{%k4}
	vplzcntq	(%ecx){1to2}, %xmm5
	vplzcntq	0x10(%edx){1to2}, %xmm3{%k5}
	vplzcntq	0x88(%ecx){1to2}, %xmm3{%k5}{z}

	vplzcntq	%ymm0, %ymm1
	vplzcntq	%ymm2, %ymm3{%k1}
	vplzcntq	%ymm4, %ymm5{%k2}{z}
	vplzcntq	(%eax), %ymm6
	vplzcntq	0x167(%eax), %ymm6{%k3}
	vplzcntq	-0x23(%eax,%ebx,4), %ymm7{%k4}
	vplzcntq	(%ecx){1to4}, %ymm5
	vplzcntq	0x10(%edx){1to4}, %ymm3{%k5}
	vplzcntq	0x88(%ecx){1to4}, %ymm3{%k5}{z}

	vplzcntq	%zmm0, %zmm1
	vplzcntq	%zmm2, %zmm3{%k1}
	vplzcntq	%zmm4, %zmm5{%k2}{z}
	vplzcntq	(%eax), %zmm6
	vplzcntq	0x167(%eax), %zmm6{%k3}
	vplzcntq	-0x23(%eax,%ebx,4), %zmm7{%k4}
	vplzcntq	(%ecx){1to8}, %zmm5
	vplzcntq	0x10(%edx){1to8}, %zmm3{%k5}
	vplzcntq	0x88(%ecx){1to8}, %zmm3{%k5}{z}

	vpbroadcastmb2q	%k1, %xmm1
	vpbroadcastmb2q	%k2, %xmm4
	vpbroadcastmb2q	%k3, %ymm2
	vpbroadcastmb2q	%k4, %ymm5
	vpbroadcastmb2q	%k5, %zmm3
	vpbroadcastmb2q	%k6, %zmm6

	vpbroadcastmw2d	%k1, %xmm1
	vpbroadcastmw2d	%k2, %xmm4
	vpbroadcastmw2d	%k3, %ymm2
	vpbroadcastmw2d	%k4, %ymm5
	vpbroadcastmw2d	%k5, %zmm3
	vpbroadcastmw2d	%k6, %zmm6
.size libdis_test, [.-libdis_test]
