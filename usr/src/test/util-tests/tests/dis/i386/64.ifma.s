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
 * AVX-512 Integer Fused Multiply Accumulate (IFMA) instructions.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	vpmadd52huq	%xmm0, %xmm1, %xmm2
	vpmadd52huq	%xmm3, %xmm4, %xmm5{%k1}
	vpmadd52huq	%xmm23, %xmm24, %xmm25{%k2}{z}
	vpmadd52huq	(%rax), %xmm16, %xmm17{%k5}{z}
	vpmadd52huq	0x23(%rax), %xmm18, %xmm19{%k3}
	vpmadd52huq	0x123(%rax,%rbx,4), %xmm3, %xmm30
	vpmadd52huq	(%rax){1to2}, %xmm6, %xmm7
	vpmadd52huq	0x54(%rax){1to2}, %xmm6, %xmm7{%k4}

	vpmadd52huq	%ymm0, %ymm1, %ymm2
	vpmadd52huq	%ymm3, %ymm4, %ymm5{%k1}
	vpmadd52huq	%ymm23, %ymm24, %ymm25{%k2}{z}
	vpmadd52huq	(%rax), %ymm16, %ymm17{%k5}{z}
	vpmadd52huq	0x23(%rax), %ymm18, %ymm19{%k3}
	vpmadd52huq	0x123(%rax,%rbx,4), %ymm3, %ymm30
	vpmadd52huq	(%rax){1to4}, %ymm6, %ymm7
	vpmadd52huq	0x54(%rax){1to4}, %ymm6, %ymm7{%k4}

	vpmadd52huq	%zmm0, %zmm1, %zmm2
	vpmadd52huq	%zmm3, %zmm4, %zmm5{%k1}
	vpmadd52huq	%zmm23, %zmm24, %zmm25{%k2}{z}
	vpmadd52huq	(%rax), %zmm16, %zmm17{%k5}{z}
	vpmadd52huq	0x23(%rax), %zmm18, %zmm19{%k3}
	vpmadd52huq	0x123(%rax,%rbx,4), %zmm3, %zmm30
	vpmadd52huq	(%rax){1to8}, %zmm6, %zmm7
	vpmadd52huq	0x54(%rax){1to8}, %zmm6, %zmm7{%k4}

	vpmadd52luq	%xmm0, %xmm1, %xmm2
	vpmadd52luq	%xmm3, %xmm4, %xmm5{%k1}
	vpmadd52luq	%xmm23, %xmm24, %xmm25{%k2}{z}
	vpmadd52luq	(%rax), %xmm16, %xmm17{%k5}{z}
	vpmadd52luq	0x23(%rax), %xmm18, %xmm19{%k3}
	vpmadd52luq	0x123(%rax,%rbx,4), %xmm3, %xmm30
	vpmadd52luq	(%rax){1to2}, %xmm6, %xmm7
	vpmadd52luq	0x54(%rax){1to2}, %xmm6, %xmm7{%k4}

	vpmadd52luq	%ymm0, %ymm1, %ymm2
	vpmadd52luq	%ymm3, %ymm4, %ymm5{%k1}
	vpmadd52luq	%ymm23, %ymm24, %ymm25{%k2}{z}
	vpmadd52luq	(%rax), %ymm16, %ymm17{%k5}{z}
	vpmadd52luq	0x23(%rax), %ymm18, %ymm19{%k3}
	vpmadd52luq	0x123(%rax,%rbx,4), %ymm3, %ymm30
	vpmadd52luq	(%rax){1to4}, %ymm6, %ymm7
	vpmadd52luq	0x54(%rax){1to4}, %ymm6, %ymm7{%k4}

	vpmadd52luq	%zmm0, %zmm1, %zmm2
	vpmadd52luq	%zmm3, %zmm4, %zmm5{%k1}
	vpmadd52luq	%zmm23, %zmm24, %zmm25{%k2}{z}
	vpmadd52luq	(%rax), %zmm16, %zmm17{%k5}{z}
	vpmadd52luq	0x23(%rax), %zmm18, %zmm19{%k3}
	vpmadd52luq	0x123(%rax,%rbx,4), %zmm3, %zmm30
	vpmadd52luq	(%rax){1to8}, %zmm6, %zmm7
	vpmadd52luq	0x54(%rax){1to8}, %zmm6, %zmm7{%k4}
.size libdis_test, [.-libdis_test]
