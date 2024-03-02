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
 * AVX-512 VBMI2 instruction decoding.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	vpshldw	$0x23, %xmm0, %xmm1, %xmm2
	vpshldw	$0x23, %xmm10, %xmm11, %xmm12{%k1}
	vpshldw	$0x23, %xmm20, %xmm21, %xmm22{%k2}{z}
	vpshldw	$0x42, (%rax), %xmm4, %xmm5
	vpshldw	$0x42, 0x23(%rax), %xmm4, %xmm5{%k3}
	vpshldw	$0x42, 0x23(%rbx, %rcx, 4), %xmm4, %xmm5{%k4}{z}

	vpshldw	$0x23, %ymm0, %ymm1, %ymm2
	vpshldw	$0x23, %ymm10, %ymm11, %ymm12{%k1}
	vpshldw	$0x23, %ymm20, %ymm21, %ymm22{%k2}{z}
	vpshldw	$0x42, (%rax), %ymm4, %ymm5
	vpshldw	$0x42, 0x23(%rax), %ymm4, %ymm5{%k3}
	vpshldw	$0x42, 0x23(%rbx, %rcx, 4), %ymm4, %ymm5{%k4}{z}

	vpshldw	$0x23, %zmm0, %zmm1, %zmm2
	vpshldw	$0x23, %zmm10, %zmm11, %zmm12{%k1}
	vpshldw	$0x23, %zmm20, %zmm21, %zmm22{%k2}{z}
	vpshldw	$0x42, (%rax), %zmm4, %zmm5
	vpshldw	$0x42, 0x23(%rax), %zmm4, %zmm5{%k3}
	vpshldw	$0x42, 0x23(%rbx, %rcx, 4), %zmm4, %zmm5{%k4}{z}

	vpshldd	$0x23, %xmm0, %xmm1, %xmm2
	vpshldd	$0x23, %xmm10, %xmm11, %xmm12{%k1}
	vpshldd	$0x23, %xmm20, %xmm21, %xmm22{%k2}{z}
	vpshldd	$0x42, (%rax), %xmm4, %xmm5
	vpshldd	$0x42, 0x23(%rax), %xmm4, %xmm5{%k3}
	vpshldd	$0x42, 0x23(%rbx, %rcx, 4), %xmm4, %xmm5{%k4}{z}
	vpshldd	$0x42, (%rdx){1to4}, %xmm4, %xmm5
	vpshldd	$0x42, 0x72(%rdx){1to4}, %xmm24, %xmm25{%k5}

	vpshldd	$0x23, %ymm0, %ymm1, %ymm2
	vpshldd	$0x23, %ymm10, %ymm11, %ymm12{%k1}
	vpshldd	$0x23, %ymm20, %ymm21, %ymm22{%k2}{z}
	vpshldd	$0x42, (%rax), %ymm4, %ymm5
	vpshldd	$0x42, 0x23(%rax), %ymm4, %ymm5{%k3}
	vpshldd	$0x42, 0x23(%rbx, %rcx, 4), %ymm4, %ymm5{%k4}{z}
	vpshldd	$0x42, (%rdx){1to8}, %ymm4, %ymm5
	vpshldd	$0x42, 0x72(%rdx){1to8}, %ymm24, %ymm25{%k5}

	vpshldd	$0x23, %zmm0, %zmm1, %zmm2
	vpshldd	$0x23, %zmm10, %zmm11, %zmm12{%k1}
	vpshldd	$0x23, %zmm20, %zmm21, %zmm22{%k2}{z}
	vpshldd	$0x42, (%rax), %zmm4, %zmm5
	vpshldd	$0x42, 0x23(%rax), %zmm4, %zmm5{%k3}
	vpshldd	$0x42, 0x23(%rbx, %rcx, 4), %zmm4, %zmm5{%k4}{z}
	vpshldd	$0x42, (%rdx){1to16}, %zmm4, %zmm5
	vpshldd	$0x42, 0x72(%rdx){1to16}, %zmm24, %zmm25{%k5}

	vpshldq	$0x23, %xmm0, %xmm1, %xmm2
	vpshldq	$0x23, %xmm10, %xmm11, %xmm12{%k1}
	vpshldq	$0x23, %xmm20, %xmm21, %xmm22{%k2}{z}
	vpshldq	$0x42, (%rax), %xmm4, %xmm5
	vpshldq	$0x42, 0x23(%rax), %xmm4, %xmm5{%k3}
	vpshldq	$0x42, 0x23(%rbx, %rcx, 4), %xmm4, %xmm5{%k4}{z}
	vpshldq	$0x42, (%rdx){1to2}, %xmm4, %xmm5
	vpshldq	$0x42, 0x72(%rdx){1to2}, %xmm24, %xmm25{%k5}

	vpshldq	$0x23, %ymm0, %ymm1, %ymm2
	vpshldq	$0x23, %ymm10, %ymm11, %ymm12{%k1}
	vpshldq	$0x23, %ymm20, %ymm21, %ymm22{%k2}{z}
	vpshldq	$0x42, (%rax), %ymm4, %ymm5
	vpshldq	$0x42, 0x23(%rax), %ymm4, %ymm5{%k3}
	vpshldq	$0x42, 0x23(%rbx, %rcx, 4), %ymm4, %ymm5{%k4}{z}
	vpshldq	$0x42, (%rdx){1to4}, %ymm4, %ymm5
	vpshldq	$0x42, 0x72(%rdx){1to4}, %ymm24, %ymm25{%k5}

	vpshldq	$0x23, %zmm0, %zmm1, %zmm2
	vpshldq	$0x23, %zmm10, %zmm11, %zmm12{%k1}
	vpshldq	$0x23, %zmm20, %zmm21, %zmm22{%k2}{z}
	vpshldq	$0x42, (%rax), %zmm4, %zmm5
	vpshldq	$0x42, 0x23(%rax), %zmm4, %zmm5{%k3}
	vpshldq	$0x42, 0x23(%rbx, %rcx, 4), %zmm4, %zmm5{%k4}{z}
	vpshldq	$0x42, (%rdx){1to8}, %zmm4, %zmm5
	vpshldq	$0x42, 0x72(%rdx){1to8}, %zmm24, %zmm25{%k5}

	vpshrdw	$0x23, %xmm0, %xmm1, %xmm2
	vpshrdw	$0x23, %xmm10, %xmm11, %xmm12{%k1}
	vpshrdw	$0x23, %xmm20, %xmm21, %xmm22{%k2}{z}
	vpshrdw	$0x42, (%rax), %xmm4, %xmm5
	vpshrdw	$0x42, 0x23(%rax), %xmm4, %xmm5{%k3}
	vpshrdw	$0x42, 0x23(%rbx, %rcx, 4), %xmm4, %xmm5{%k4}{z}

	vpshrdw	$0x23, %ymm0, %ymm1, %ymm2
	vpshrdw	$0x23, %ymm10, %ymm11, %ymm12{%k1}
	vpshrdw	$0x23, %ymm20, %ymm21, %ymm22{%k2}{z}
	vpshrdw	$0x42, (%rax), %ymm4, %ymm5
	vpshrdw	$0x42, 0x23(%rax), %ymm4, %ymm5{%k3}
	vpshrdw	$0x42, 0x23(%rbx, %rcx, 4), %ymm4, %ymm5{%k4}{z}

	vpshrdw	$0x23, %zmm0, %zmm1, %zmm2
	vpshrdw	$0x23, %zmm10, %zmm11, %zmm12{%k1}
	vpshrdw	$0x23, %zmm20, %zmm21, %zmm22{%k2}{z}
	vpshrdw	$0x42, (%rax), %zmm4, %zmm5
	vpshrdw	$0x42, 0x23(%rax), %zmm4, %zmm5{%k3}
	vpshrdw	$0x42, 0x23(%rbx, %rcx, 4), %zmm4, %zmm5{%k4}{z}

	vpshrdd	$0x23, %xmm0, %xmm1, %xmm2
	vpshrdd	$0x23, %xmm10, %xmm11, %xmm12{%k1}
	vpshrdd	$0x23, %xmm20, %xmm21, %xmm22{%k2}{z}
	vpshrdd	$0x42, (%rax), %xmm4, %xmm5
	vpshrdd	$0x42, 0x23(%rax), %xmm4, %xmm5{%k3}
	vpshrdd	$0x42, 0x23(%rbx, %rcx, 4), %xmm4, %xmm5{%k4}{z}
	vpshrdd	$0x42, (%rdx){1to4}, %xmm4, %xmm5
	vpshrdd	$0x42, 0x72(%rdx){1to4}, %xmm24, %xmm25{%k5}

	vpshrdd	$0x23, %ymm0, %ymm1, %ymm2
	vpshrdd	$0x23, %ymm10, %ymm11, %ymm12{%k1}
	vpshrdd	$0x23, %ymm20, %ymm21, %ymm22{%k2}{z}
	vpshrdd	$0x42, (%rax), %ymm4, %ymm5
	vpshrdd	$0x42, 0x23(%rax), %ymm4, %ymm5{%k3}
	vpshrdd	$0x42, 0x23(%rbx, %rcx, 4), %ymm4, %ymm5{%k4}{z}
	vpshrdd	$0x42, (%rdx){1to8}, %ymm4, %ymm5
	vpshrdd	$0x42, 0x72(%rdx){1to8}, %ymm24, %ymm25{%k5}

	vpshrdd	$0x23, %zmm0, %zmm1, %zmm2
	vpshrdd	$0x23, %zmm10, %zmm11, %zmm12{%k1}
	vpshrdd	$0x23, %zmm20, %zmm21, %zmm22{%k2}{z}
	vpshrdd	$0x42, (%rax), %zmm4, %zmm5
	vpshrdd	$0x42, 0x23(%rax), %zmm4, %zmm5{%k3}
	vpshrdd	$0x42, 0x23(%rbx, %rcx, 4), %zmm4, %zmm5{%k4}{z}
	vpshrdd	$0x42, (%rdx){1to16}, %zmm4, %zmm5
	vpshrdd	$0x42, 0x72(%rdx){1to16}, %zmm24, %zmm25{%k5}

	vpshrdq	$0x23, %xmm0, %xmm1, %xmm2
	vpshrdq	$0x23, %xmm10, %xmm11, %xmm12{%k1}
	vpshrdq	$0x23, %xmm20, %xmm21, %xmm22{%k2}{z}
	vpshrdq	$0x42, (%rax), %xmm4, %xmm5
	vpshrdq	$0x42, 0x23(%rax), %xmm4, %xmm5{%k3}
	vpshrdq	$0x42, 0x23(%rbx, %rcx, 4), %xmm4, %xmm5{%k4}{z}
	vpshrdq	$0x42, (%rdx){1to2}, %xmm4, %xmm5
	vpshrdq	$0x42, 0x72(%rdx){1to2}, %xmm24, %xmm25{%k5}

	vpshrdq	$0x23, %ymm0, %ymm1, %ymm2
	vpshrdq	$0x23, %ymm10, %ymm11, %ymm12{%k1}
	vpshrdq	$0x23, %ymm20, %ymm21, %ymm22{%k2}{z}
	vpshrdq	$0x42, (%rax), %ymm4, %ymm5
	vpshrdq	$0x42, 0x23(%rax), %ymm4, %ymm5{%k3}
	vpshrdq	$0x42, 0x23(%rbx, %rcx, 4), %ymm4, %ymm5{%k4}{z}
	vpshrdq	$0x42, (%rdx){1to4}, %ymm4, %ymm5
	vpshrdq	$0x42, 0x72(%rdx){1to4}, %ymm24, %ymm25{%k5}

	vpshrdq	$0x23, %zmm0, %zmm1, %zmm2
	vpshrdq	$0x23, %zmm10, %zmm11, %zmm12{%k1}
	vpshrdq	$0x23, %zmm20, %zmm21, %zmm22{%k2}{z}
	vpshrdq	$0x42, (%rax), %zmm4, %zmm5
	vpshrdq	$0x42, 0x23(%rax), %zmm4, %zmm5{%k3}
	vpshrdq	$0x42, 0x23(%rbx, %rcx, 4), %zmm4, %zmm5{%k4}{z}
	vpshrdq	$0x42, (%rdx){1to8}, %zmm4, %zmm5
	vpshrdq	$0x42, 0x72(%rdx){1to8}, %zmm24, %zmm25{%k5}

	vpcompressb	%xmm0, %xmm1
	vpcompressb	%xmm1, %xmm2{%k1}
	vpcompressb	%xmm2, %xmm3{%k2}{z}
	vpcompressb	%xmm4, (%rax)
	vpcompressb	%xmm5, (%rax){%k3}
	vpcompressb	%xmm6, 0x23(%rax)
	vpcompressb	%xmm6, 0x24(%rax)
	vpcompressb	%xmm7, 0x42(%rax){%k3}

	vpcompressb	%ymm0, %ymm1
	vpcompressb	%ymm1, %ymm2{%k1}
	vpcompressb	%ymm2, %ymm3{%k2}{z}
	vpcompressb	%ymm4, (%rax)
	vpcompressb	%ymm5, (%rax){%k3}
	vpcompressb	%ymm6, 0x23(%rax)
	vpcompressb	%ymm6, 0x24(%rax)
	vpcompressb	%ymm7, 0x42(%rax){%k3}

	vpcompressb	%zmm0, %zmm1
	vpcompressb	%zmm1, %zmm2{%k1}
	vpcompressb	%zmm2, %zmm3{%k2}{z}
	vpcompressb	%zmm4, (%rax)
	vpcompressb	%zmm5, (%rax){%k3}
	vpcompressb	%zmm6, 0x23(%rax)
	vpcompressb	%zmm6, 0x24(%rax)
	vpcompressb	%zmm7, 0x42(%rax){%k3}

	vpcompressw	%xmm0, %xmm1
	vpcompressw	%xmm1, %xmm2{%k1}
	vpcompressw	%xmm2, %xmm3{%k2}{z}
	vpcompressw	%xmm4, (%rax)
	vpcompressw	%xmm5, (%rax){%k3}
	vpcompressw	%xmm6, 0x23(%rax)
	vpcompressw	%xmm6, 0x24(%rax)
	vpcompressw	%xmm7, 0x42(%rax){%k3}

	vpcompressw	%ymm0, %ymm1
	vpcompressw	%ymm1, %ymm2{%k1}
	vpcompressw	%ymm2, %ymm3{%k2}{z}
	vpcompressw	%ymm4, (%rax)
	vpcompressw	%ymm5, (%rax){%k3}
	vpcompressw	%ymm6, 0x23(%rax)
	vpcompressw	%ymm6, 0x24(%rax)
	vpcompressw	%ymm7, 0x42(%rax){%k3}

	vpcompressw	%zmm0, %zmm1
	vpcompressw	%zmm1, %zmm2{%k1}
	vpcompressw	%zmm2, %zmm3{%k2}{z}
	vpcompressw	%zmm4, (%rax)
	vpcompressw	%zmm5, (%rax){%k3}
	vpcompressw	%zmm6, 0x23(%rax)
	vpcompressw	%zmm6, 0x24(%rax)
	vpcompressw	%zmm7, 0x42(%rax){%k3}

	vpexpandb	%xmm0, %xmm1
	vpexpandb	%xmm1, %xmm2{%k1}
	vpexpandb	%xmm2, %xmm3{%k2}{z}
	vpexpandb	(%rax), %xmm4
	vpexpandb	(%rax), %xmm5{%k3}
	vpexpandb	0x23(%rax), %xmm6
	vpexpandb	0x24(%rax), %xmm6
	vpexpandb	0x42(%rax), %xmm7{%k3}{z}

	vpexpandb	%ymm0, %ymm1
	vpexpandb	%ymm1, %ymm2{%k1}
	vpexpandb	%ymm2, %ymm3{%k2}{z}
	vpexpandb	(%rax), %ymm4
	vpexpandb	(%rax), %ymm5{%k3}
	vpexpandb	0x23(%rax), %ymm6
	vpexpandb	0x24(%rax), %ymm6
	vpexpandb	0x42(%rax), %ymm7{%k3}{z}

	vpexpandb	%zmm0, %zmm1
	vpexpandb	%zmm1, %zmm2{%k1}
	vpexpandb	%zmm2, %zmm3{%k2}{z}
	vpexpandb	(%rax), %zmm4
	vpexpandb	(%rax), %zmm5{%k3}
	vpexpandb	0x23(%rax), %zmm6
	vpexpandb	0x24(%rax), %zmm6
	vpexpandb	0x42(%rax), %zmm7{%k3}{z}

	vpshldvw	%xmm0, %xmm1, %xmm2
	vpshldvw	%xmm10, %xmm11, %xmm12{%k1}
	vpshldvw	%xmm20, %xmm21, %xmm22{%k2}{z}
	vpshldvw	(%rax), %xmm4, %xmm5
	vpshldvw	0x23(%rax), %xmm4, %xmm5{%k3}
	vpshldvw	0x23(%rbx, %rcx, 4), %xmm4, %xmm5{%k4}{z}

	vpshldvw	%ymm0, %ymm1, %ymm2
	vpshldvw	%ymm10, %ymm11, %ymm12{%k1}
	vpshldvw	%ymm20, %ymm21, %ymm22{%k2}{z}
	vpshldvw	(%rax), %ymm4, %ymm5
	vpshldvw	0x23(%rax), %ymm4, %ymm5{%k3}
	vpshldvw	0x23(%rbx, %rcx, 4), %ymm4, %ymm5{%k4}{z}

	vpshldvw	%zmm0, %zmm1, %zmm2
	vpshldvw	%zmm10, %zmm11, %zmm12{%k1}
	vpshldvw	%zmm20, %zmm21, %zmm22{%k2}{z}
	vpshldvw	(%rax), %zmm4, %zmm5
	vpshldvw	0x23(%rax), %zmm4, %zmm5{%k3}
	vpshldvw	0x23(%rbx, %rcx, 4), %zmm4, %zmm5{%k4}{z}

	vpshldvd	%xmm0, %xmm1, %xmm2
	vpshldvd	%xmm10, %xmm11, %xmm12{%k1}
	vpshldvd	%xmm20, %xmm21, %xmm22{%k2}{z}
	vpshldvd	(%rax), %xmm4, %xmm5
	vpshldvd	0x23(%rax), %xmm4, %xmm5{%k3}
	vpshldvd	0x23(%rbx, %rcx, 4), %xmm4, %xmm5{%k4}{z}
	vpshldvd	(%rdx){1to4}, %xmm4, %xmm5
	vpshldvd	0x72(%rdx){1to4}, %xmm24, %xmm25{%k5}

	vpshldvd	%ymm0, %ymm1, %ymm2
	vpshldvd	%ymm10, %ymm11, %ymm12{%k1}
	vpshldvd	%ymm20, %ymm21, %ymm22{%k2}{z}
	vpshldvd	(%rax), %ymm4, %ymm5
	vpshldvd	0x23(%rax), %ymm4, %ymm5{%k3}
	vpshldvd	0x23(%rbx, %rcx, 4), %ymm4, %ymm5{%k4}{z}
	vpshldvd	(%rdx){1to8}, %ymm4, %ymm5
	vpshldvd	0x72(%rdx){1to8}, %ymm24, %ymm25{%k5}

	vpshldvd	%zmm0, %zmm1, %zmm2
	vpshldvd	%zmm10, %zmm11, %zmm12{%k1}
	vpshldvd	%zmm20, %zmm21, %zmm22{%k2}{z}
	vpshldvd	(%rax), %zmm4, %zmm5
	vpshldvd	0x23(%rax), %zmm4, %zmm5{%k3}
	vpshldvd	0x23(%rbx, %rcx, 4), %zmm4, %zmm5{%k4}{z}
	vpshldvd	(%rdx){1to16}, %zmm4, %zmm5
	vpshldvd	0x72(%rdx){1to16}, %zmm24, %zmm25{%k5}

	vpshldvq	%xmm0, %xmm1, %xmm2
	vpshldvq	%xmm10, %xmm11, %xmm12{%k1}
	vpshldvq	%xmm20, %xmm21, %xmm22{%k2}{z}
	vpshldvq	(%rax), %xmm4, %xmm5
	vpshldvq	0x23(%rax), %xmm4, %xmm5{%k3}
	vpshldvq	0x23(%rbx, %rcx, 4), %xmm4, %xmm5{%k4}{z}
	vpshldvq	(%rdx){1to2}, %xmm4, %xmm5
	vpshldvq	0x72(%rdx){1to2}, %xmm24, %xmm25{%k5}

	vpshldvq	%ymm0, %ymm1, %ymm2
	vpshldvq	%ymm10, %ymm11, %ymm12{%k1}
	vpshldvq	%ymm20, %ymm21, %ymm22{%k2}{z}
	vpshldvq	(%rax), %ymm4, %ymm5
	vpshldvq	0x23(%rax), %ymm4, %ymm5{%k3}
	vpshldvq	0x23(%rbx, %rcx, 4), %ymm4, %ymm5{%k4}{z}
	vpshldvq	(%rdx){1to4}, %ymm4, %ymm5
	vpshldvq	0x72(%rdx){1to4}, %ymm24, %ymm25{%k5}

	vpshldvq	%zmm0, %zmm1, %zmm2
	vpshldvq	%zmm10, %zmm11, %zmm12{%k1}
	vpshldvq	%zmm20, %zmm21, %zmm22{%k2}{z}
	vpshldvq	(%rax), %zmm4, %zmm5
	vpshldvq	0x23(%rax), %zmm4, %zmm5{%k3}
	vpshldvq	0x23(%rbx, %rcx, 4), %zmm4, %zmm5{%k4}{z}
	vpshldvq	(%rdx){1to8}, %zmm4, %zmm5
	vpshldvq	0x72(%rdx){1to8}, %zmm24, %zmm25{%k5}

	vpshrdvw	%xmm0, %xmm1, %xmm2
	vpshrdvw	%xmm10, %xmm11, %xmm12{%k1}
	vpshrdvw	%xmm20, %xmm21, %xmm22{%k2}{z}
	vpshrdvw	(%rax), %xmm4, %xmm5
	vpshrdvw	0x23(%rax), %xmm4, %xmm5{%k3}
	vpshrdvw	0x23(%rbx, %rcx, 4), %xmm4, %xmm5{%k4}{z}

	vpshrdvw	%ymm0, %ymm1, %ymm2
	vpshrdvw	%ymm10, %ymm11, %ymm12{%k1}
	vpshrdvw	%ymm20, %ymm21, %ymm22{%k2}{z}
	vpshrdvw	(%rax), %ymm4, %ymm5
	vpshrdvw	0x23(%rax), %ymm4, %ymm5{%k3}
	vpshrdvw	0x23(%rbx, %rcx, 4), %ymm4, %ymm5{%k4}{z}

	vpshrdvw	%zmm0, %zmm1, %zmm2
	vpshrdvw	%zmm10, %zmm11, %zmm12{%k1}
	vpshrdvw	%zmm20, %zmm21, %zmm22{%k2}{z}
	vpshrdvw	(%rax), %zmm4, %zmm5
	vpshrdvw	0x23(%rax), %zmm4, %zmm5{%k3}
	vpshrdvw	0x23(%rbx, %rcx, 4), %zmm4, %zmm5{%k4}{z}

	vpshrdvd	%xmm0, %xmm1, %xmm2
	vpshrdvd	%xmm10, %xmm11, %xmm12{%k1}
	vpshrdvd	%xmm20, %xmm21, %xmm22{%k2}{z}
	vpshrdvd	(%rax), %xmm4, %xmm5
	vpshrdvd	0x23(%rax), %xmm4, %xmm5{%k3}
	vpshrdvd	0x23(%rbx, %rcx, 4), %xmm4, %xmm5{%k4}{z}
	vpshrdvd	(%rdx){1to4}, %xmm4, %xmm5
	vpshrdvd	0x72(%rdx){1to4}, %xmm24, %xmm25{%k5}

	vpshrdvd	%ymm0, %ymm1, %ymm2
	vpshrdvd	%ymm10, %ymm11, %ymm12{%k1}
	vpshrdvd	%ymm20, %ymm21, %ymm22{%k2}{z}
	vpshrdvd	(%rax), %ymm4, %ymm5
	vpshrdvd	0x23(%rax), %ymm4, %ymm5{%k3}
	vpshrdvd	0x23(%rbx, %rcx, 4), %ymm4, %ymm5{%k4}{z}
	vpshrdvd	(%rdx){1to8}, %ymm4, %ymm5
	vpshrdvd	0x72(%rdx){1to8}, %ymm24, %ymm25{%k5}

	vpshrdvd	%zmm0, %zmm1, %zmm2
	vpshrdvd	%zmm10, %zmm11, %zmm12{%k1}
	vpshrdvd	%zmm20, %zmm21, %zmm22{%k2}{z}
	vpshrdvd	(%rax), %zmm4, %zmm5
	vpshrdvd	0x23(%rax), %zmm4, %zmm5{%k3}
	vpshrdvd	0x23(%rbx, %rcx, 4), %zmm4, %zmm5{%k4}{z}
	vpshrdvd	(%rdx){1to16}, %zmm4, %zmm5
	vpshrdvd	0x72(%rdx){1to16}, %zmm24, %zmm25{%k5}

	vpshrdvq	%xmm0, %xmm1, %xmm2
	vpshrdvq	%xmm10, %xmm11, %xmm12{%k1}
	vpshrdvq	%xmm20, %xmm21, %xmm22{%k2}{z}
	vpshrdvq	(%rax), %xmm4, %xmm5
	vpshrdvq	0x23(%rax), %xmm4, %xmm5{%k3}
	vpshrdvq	0x23(%rbx, %rcx, 4), %xmm4, %xmm5{%k4}{z}
	vpshrdvq	(%rdx){1to2}, %xmm4, %xmm5
	vpshrdvq	0x72(%rdx){1to2}, %xmm24, %xmm25{%k5}

	vpshrdvq	%ymm0, %ymm1, %ymm2
	vpshrdvq	%ymm10, %ymm11, %ymm12{%k1}
	vpshrdvq	%ymm20, %ymm21, %ymm22{%k2}{z}
	vpshrdvq	(%rax), %ymm4, %ymm5
	vpshrdvq	0x23(%rax), %ymm4, %ymm5{%k3}
	vpshrdvq	0x23(%rbx, %rcx, 4), %ymm4, %ymm5{%k4}{z}
	vpshrdvq	(%rdx){1to4}, %ymm4, %ymm5
	vpshrdvq	0x80(%rdx){1to4}, %ymm24, %ymm25{%k5}

	vpshrdvq	%zmm0, %zmm1, %zmm2
	vpshrdvq	%zmm10, %zmm11, %zmm12{%k1}
	vpshrdvq	%zmm20, %zmm21, %zmm22{%k2}{z}
	vpshrdvq	(%rax), %zmm4, %zmm5
	vpshrdvq	0x23(%rax), %zmm4, %zmm5{%k3}
	vpshrdvq	0x23(%rbx, %rcx, 4), %zmm4, %zmm5{%k4}{z}
	vpshrdvq	(%rdx){1to8}, %zmm4, %zmm5
	vpshrdvq	0x72(%rdx){1to8}, %zmm24, %zmm25{%k5}
.size libdis_test, [.-libdis_test]
