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
 * Copyright 2019 Joyent, Inc.
 * Copyright 2024 Oxide Computer Company
 */

/*
 * 32-bit AVX-512 VNNI instruction disassembly.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	vpdpbusd	%xmm0, %xmm1, %xmm2
	vpdpbusd	%ymm3, %ymm4, %ymm5
	vpdpbusd	%zmm6, %zmm7, %zmm0
	vpdpbusd	%xmm1, %xmm2, %xmm3{%k1}
	vpdpbusd	%xmm4, %xmm5, %xmm6{%k2}{z}
	vpdpbusd	%ymm7, %ymm0, %ymm1{%k3}
	vpdpbusd	%ymm2, %ymm3, %ymm4{%k4}{z}
	vpdpbusd	%zmm5, %zmm6, %zmm7{%k5}
	vpdpbusd	%zmm0, %zmm1, %zmm2{%k6}{z}
	vpdpbusd	0x64(%eax), %zmm3, %zmm4
	vpdpbusd	0x123456(%ebx, %ecx, 8), %zmm5, %zmm6
	vpdpbusd	(%edx){1to4}, %xmm1, %xmm2
	vpdpbusd	0x23(%edx){1to4}, %xmm1, %xmm2
	vpdpbusd	(%edx){1to8}, %ymm1, %ymm2
	vpdpbusd	0x23(%edx){1to8}, %ymm1, %ymm2
	vpdpbusd	(%edx){1to16}, %zmm1, %zmm2
	vpdpbusd	0x23(%edx){1to16}, %zmm1, %zmm2

	vpdpbusds	%xmm0, %xmm1, %xmm2
	vpdpbusds	%ymm3, %ymm4, %ymm5
	vpdpbusds	%zmm6, %zmm7, %zmm0
	vpdpbusds	%xmm1, %xmm2, %xmm3{%k1}
	vpdpbusds	%xmm4, %xmm5, %xmm6{%k2}{z}
	vpdpbusds	%ymm7, %ymm0, %ymm1{%k3}
	vpdpbusds	%ymm2, %ymm3, %ymm4{%k4}{z}
	vpdpbusds	%zmm5, %zmm6, %zmm7{%k5}
	vpdpbusds	%zmm0, %zmm1, %zmm2{%k6}{z}
	vpdpbusds	0x64(%eax), %zmm3, %zmm4
	vpdpbusds	0x123456(%ebx, %ecx, 8), %zmm5, %zmm6
	vpdpbusds	(%edx){1to4}, %xmm1, %xmm2
	vpdpbusds	0x23(%edx){1to4}, %xmm1, %xmm2
	vpdpbusds	(%edx){1to8}, %ymm1, %ymm2
	vpdpbusds	0x23(%edx){1to8}, %ymm1, %ymm2
	vpdpbusds	(%edx){1to16}, %zmm1, %zmm2
	vpdpbusds	0x23(%edx){1to16}, %zmm1, %zmm2

	vpdpwssd	%xmm0, %xmm1, %xmm2
	vpdpwssd	%ymm3, %ymm4, %ymm5
	vpdpwssd	%zmm6, %zmm7, %zmm0
	vpdpwssd	%xmm1, %xmm2, %xmm3{%k1}
	vpdpwssd	%xmm4, %xmm5, %xmm6{%k2}{z}
	vpdpwssd	%ymm7, %ymm0, %ymm1{%k3}
	vpdpwssd	%ymm2, %ymm3, %ymm4{%k4}{z}
	vpdpwssd	%zmm5, %zmm6, %zmm7{%k5}
	vpdpwssd	%zmm0, %zmm1, %zmm2{%k6}{z}
	vpdpwssd	0x64(%eax), %zmm3, %zmm4
	vpdpwssd	0x123456(%ebx, %ecx, 8), %zmm5, %zmm6
	vpdpwssd	(%edx){1to4}, %xmm1, %xmm2
	vpdpwssd	0x23(%edx){1to4}, %xmm1, %xmm2
	vpdpwssd	(%edx){1to8}, %ymm1, %ymm2
	vpdpwssd	0x23(%edx){1to8}, %ymm1, %ymm2
	vpdpwssd	(%edx){1to16}, %zmm1, %zmm2
	vpdpwssd	0x23(%edx){1to16}, %zmm1, %zmm2

	vpdpwssds	%xmm0, %xmm1, %xmm2
	vpdpwssds	%ymm3, %ymm4, %ymm5
	vpdpwssds	%zmm6, %zmm7, %zmm0
	vpdpwssds	%xmm1, %xmm2, %xmm3{%k1}
	vpdpwssds	%xmm4, %xmm5, %xmm6{%k2}{z}
	vpdpwssds	%ymm7, %ymm0, %ymm1{%k3}
	vpdpwssds	%ymm2, %ymm3, %ymm4{%k4}{z}
	vpdpwssds	%zmm5, %zmm6, %zmm7{%k5}
	vpdpwssds	%zmm0, %zmm1, %zmm2{%k6}{z}
	vpdpwssds	0x64(%eax), %zmm3, %zmm4
	vpdpwssds	0x123456(%ebx, %ecx, 8), %zmm5, %zmm6
	vpdpwssds	(%edx){1to4}, %xmm1, %xmm2
	vpdpwssds	0x23(%edx){1to4}, %xmm1, %xmm2
	vpdpwssds	(%edx){1to8}, %ymm1, %ymm2
	vpdpwssds	0x23(%edx){1to8}, %ymm1, %ymm2
	vpdpwssds	(%edx){1to16}, %zmm1, %zmm2
	vpdpwssds	0x23(%edx){1to16}, %zmm1, %zmm2
.size libdis_test, [.-libdis_test]
