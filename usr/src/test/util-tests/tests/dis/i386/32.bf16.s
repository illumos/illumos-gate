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
 * Binary floating point 16 instructions, currently just AVX related (i.e. no AMX).
 *
 * For the vcvtneps2bf16 instruction, gas sometimes has a variant with 'x' or
 * 'y' appended which appear to be an indication for the target memory size,
 * particularly for broadcasts and related. While we use those (as there's no
 * other way to get that), dis currently does not break these apart.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	vcvtne2ps2bf16	%xmm0, %xmm1, %xmm2
	vcvtne2ps2bf16	%xmm3, %xmm4, %xmm5{%k1}
	vcvtne2ps2bf16	%xmm6, %xmm7, %xmm0{%k2}{z}
	vcvtne2ps2bf16	(%eax), %xmm1, %xmm2
	vcvtne2ps2bf16	0x77(%ebx), %xmm1, %xmm2
	vcvtne2ps2bf16	0x77(%ecx,%edx,4), %xmm1, %xmm2
	vcvtne2ps2bf16	0x7777(%edi){1to4}, %xmm1, %xmm2
	vcvtne2ps2bf16	0x7777(%edi){1to4}, %xmm1, %xmm2{%k3}
	vcvtne2ps2bf16	0x7777(%edi){1to4}, %xmm1, %xmm2{%k3}{z}

	vcvtne2ps2bf16	%ymm0, %ymm1, %ymm2
	vcvtne2ps2bf16	%ymm3, %ymm4, %ymm5{%k1}
	vcvtne2ps2bf16	%ymm6, %ymm7, %ymm0{%k2}{z}
	vcvtne2ps2bf16	(%eax), %ymm1, %ymm2
	vcvtne2ps2bf16	0x77(%ebx), %ymm1, %ymm2
	vcvtne2ps2bf16	0x77(%ecx,%edx,4), %ymm1, %ymm2
	vcvtne2ps2bf16	0x7777(%edi){1to8}, %ymm1, %ymm2

	vcvtne2ps2bf16	%zmm0, %zmm1, %zmm2
	vcvtne2ps2bf16	%zmm3, %zmm4, %zmm5{%k1}
	vcvtne2ps2bf16	%zmm6, %zmm7, %zmm0{%k2}{z}
	vcvtne2ps2bf16	(%eax), %zmm1, %zmm2
	vcvtne2ps2bf16	0x77(%ebx), %zmm1, %zmm2
	vcvtne2ps2bf16	0x77(%ecx,%edx,4), %zmm1, %zmm2
	vcvtne2ps2bf16	0x7777(%edi){1to16}, %zmm1, %zmm2

	vcvtneps2bf16	%xmm0, %xmm1
	vcvtneps2bf16	%xmm2, %xmm3{%k4}
	vcvtneps2bf16	%xmm5, %xmm6{%k7}{z}
	vcvtneps2bf16x	(%edi), %xmm7
	vcvtneps2bf16x	0x88(%ebx), %xmm6
	vcvtneps2bf16x	0x88(%ebx,%ecx,4), %xmm5
	vcvtneps2bf16x	0x66(%ebx,%ecx,4), %xmm5{%k3}
	vcvtneps2bf16	(%esi){1to4}, %xmm6
	vcvtneps2bf16	(%esi){1to4}, %xmm6{%k6}
	vcvtneps2bf16	(%edi){1to8}, %xmm6

	vcvtneps2bf16	%ymm0, %xmm1
	vcvtneps2bf16	%ymm2, %xmm3{%k4}
	vcvtneps2bf16	%ymm5, %xmm6{%k7}{z}
	vcvtneps2bf16y	(%edi), %xmm7
	vcvtneps2bf16y	0x88(%ebx), %xmm6
	vcvtneps2bf16y	0x88(%ebx,%ecx,4), %xmm5
	vcvtneps2bf16y	-0x66(%ebx,%ecx,4), %xmm5{%k3}
	vcvtneps2bf16	(%esi){1to8}, %xmm6
	vcvtneps2bf16	(%esi){1to8}, %xmm6{%k6}

	vcvtneps2bf16	%zmm0, %ymm1
	vcvtneps2bf16	%zmm2, %ymm3{%k4}
	vcvtneps2bf16	%zmm5, %ymm6{%k7}{z}
	vcvtneps2bf16	(%edi), %ymm7
	vcvtneps2bf16	0x88(%ebx), %ymm6
	vcvtneps2bf16	0x88(%ebx,%ecx,4), %ymm5
	vcvtneps2bf16	-0x66(%ebx,%ecx,4), %ymm5{%k3}
	vcvtneps2bf16	(%esi){1to16}, %ymm6
	vcvtneps2bf16	(%esi){1to16}, %ymm6{%k6}

	vdpbf16ps	%xmm0, %xmm1, %xmm2
	vdpbf16ps	%xmm3, %xmm4, %xmm5{%k1}
	vdpbf16ps	%xmm6, %xmm7, %xmm0{%k2}{z}
	vdpbf16ps	(%eax), %xmm1, %xmm2
	vdpbf16ps	0x77(%ebx), %xmm1, %xmm2
	vdpbf16ps	0x77(%ecx,%edx,4), %xmm1, %xmm2
	vdpbf16ps	0x7777(%edi){1to4}, %xmm1, %xmm2
	vdpbf16ps	0x7777(%edi){1to4}, %xmm1, %xmm2{%k3}
	vdpbf16ps	0x7777(%edi){1to4}, %xmm1, %xmm2{%k3}{z}

	vdpbf16ps	%ymm0, %ymm1, %ymm2
	vdpbf16ps	%ymm3, %ymm4, %ymm5{%k1}
	vdpbf16ps	%ymm6, %ymm7, %ymm0{%k2}{z}
	vdpbf16ps	(%eax), %ymm1, %ymm2
	vdpbf16ps	0x77(%ebx), %ymm1, %ymm2
	vdpbf16ps	0x77(%ecx,%edx,4), %ymm1, %ymm2
	vdpbf16ps	0x7777(%edi){1to8}, %ymm1, %ymm2

	vdpbf16ps	%zmm0, %zmm1, %zmm2
	vdpbf16ps	%zmm3, %zmm4, %zmm5{%k1}
	vdpbf16ps	%zmm6, %zmm7, %zmm0{%k2}{z}
	vdpbf16ps	(%eax), %zmm1, %zmm2
	vdpbf16ps	0x77(%ebx), %zmm1, %zmm2
	vdpbf16ps	0x77(%ecx,%edx,4), %zmm1, %zmm2
	vdpbf16ps	0x7777(%edi){1to16}, %zmm1, %zmm2
.size libdis_test, [.-libdis_test]
