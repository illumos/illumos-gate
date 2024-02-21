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
 * 64-bit AVX-512 VNNI instruction disassembly.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	vpdpbusd	%xmm0, %xmm1, %xmm2
	vpdpbusd	%ymm3, %ymm4, %ymm5
	vpdpbusd	%zmm6, %zmm7, %zmm8
	vpdpbusd	%xmm9, %xmm10, %xmm11{%k1}
	vpdpbusd	%xmm12, %xmm13, %xmm14{%k2}{z}
	vpdpbusd	%ymm15, %ymm16, %ymm17{%k3}
	vpdpbusd	%ymm18, %ymm19, %ymm20{%k4}{z}
	vpdpbusd	%zmm21, %zmm22, %zmm23{%k5}
	vpdpbusd	%zmm24, %zmm25, %zmm26{%k6}{z}
	vpdpbusd	0x64(%rax), %zmm27, %zmm28
	vpdpbusd	0x123456(%rbx, %rcx, 8), %zmm29, %zmm30
	vpdpbusd	(%rdx){1to4}, %xmm1, %xmm2
	vpdpbusd	0x23(%rdx){1to4}, %xmm1, %xmm2
	vpdpbusd	(%rdx){1to8}, %ymm1, %ymm2
	vpdpbusd	0x23(%rdx){1to8}, %ymm1, %ymm2
	vpdpbusd	(%rdx){1to16}, %zmm1, %zmm2
	vpdpbusd	0x23(%rdx){1to16}, %zmm1, %zmm2

	vpdpbusds	%xmm0, %xmm1, %xmm2
	vpdpbusds	%ymm3, %ymm4, %ymm5
	vpdpbusds	%zmm6, %zmm7, %zmm8
	vpdpbusds	%xmm9, %xmm10, %xmm11{%k1}
	vpdpbusds	%xmm12, %xmm13, %xmm14{%k2}{z}
	vpdpbusds	%ymm15, %ymm16, %ymm17{%k3}
	vpdpbusds	%ymm18, %ymm19, %ymm20{%k4}{z}
	vpdpbusds	%zmm21, %zmm22, %zmm23{%k5}
	vpdpbusds	%zmm24, %zmm25, %zmm26{%k6}{z}
	vpdpbusds	0x64(%rax), %zmm27, %zmm28
	vpdpbusds	0x123456(%rbx, %rcx, 8), %zmm29, %zmm30
	vpdpbusds	(%rdx){1to4}, %xmm1, %xmm2
	vpdpbusds	0x23(%rdx){1to4}, %xmm1, %xmm2
	vpdpbusds	(%rdx){1to8}, %ymm1, %ymm2
	vpdpbusds	0x23(%rdx){1to8}, %ymm1, %ymm2
	vpdpbusds	(%rdx){1to16}, %zmm1, %zmm2
	vpdpbusds	0x23(%rdx){1to16}, %zmm1, %zmm2

	vpdpwssd	%xmm0, %xmm1, %xmm2
	vpdpwssd	%ymm3, %ymm4, %ymm5
	vpdpwssd	%zmm6, %zmm7, %zmm8
	vpdpwssd	%xmm9, %xmm10, %xmm11{%k1}
	vpdpwssd	%xmm12, %xmm13, %xmm14{%k2}{z}
	vpdpwssd	%ymm15, %ymm16, %ymm17{%k3}
	vpdpwssd	%ymm18, %ymm19, %ymm20{%k4}{z}
	vpdpwssd	%zmm21, %zmm22, %zmm23{%k5}
	vpdpwssd	%zmm24, %zmm25, %zmm26{%k6}{z}
	vpdpwssd	0x64(%rax), %zmm27, %zmm28
	vpdpwssd	0x123456(%rbx, %rcx, 8), %zmm29, %zmm30
	vpdpwssd	(%rdx){1to4}, %xmm1, %xmm2
	vpdpwssd	0x23(%rdx){1to4}, %xmm1, %xmm2
	vpdpwssd	(%rdx){1to8}, %ymm1, %ymm2
	vpdpwssd	0x23(%rdx){1to8}, %ymm1, %ymm2
	vpdpwssd	(%rdx){1to16}, %zmm1, %zmm2
	vpdpwssd	0x23(%rdx){1to16}, %zmm1, %zmm2

	vpdpwssds	%xmm0, %xmm1, %xmm2
	vpdpwssds	%ymm3, %ymm4, %ymm5
	vpdpwssds	%zmm6, %zmm7, %zmm8
	vpdpwssds	%xmm9, %xmm10, %xmm11{%k1}
	vpdpwssds	%xmm12, %xmm13, %xmm14{%k2}{z}
	vpdpwssds	%ymm15, %ymm16, %ymm17{%k3}
	vpdpwssds	%ymm18, %ymm19, %ymm20{%k4}{z}
	vpdpwssds	%zmm21, %zmm22, %zmm23{%k5}
	vpdpwssds	%zmm24, %zmm25, %zmm26{%k6}{z}
	vpdpwssds	0x64(%rax), %zmm27, %zmm28
	vpdpwssds	0x123456(%rbx, %rcx, 8), %zmm29, %zmm30
	vpdpwssds	(%rdx){1to4}, %xmm1, %xmm2
	vpdpwssds	0x23(%rdx){1to4}, %xmm1, %xmm2
	vpdpwssds	(%rdx){1to8}, %ymm1, %ymm2
	vpdpwssds	0x23(%rdx){1to8}, %ymm1, %ymm2
	vpdpwssds	(%rdx){1to16}, %zmm1, %zmm2
	vpdpwssds	0x23(%rdx){1to16}, %zmm1, %zmm2
.size libdis_test, [.-libdis_test]
