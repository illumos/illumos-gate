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
	vpshldw	$0x23, %xmm2, %xmm3, %xmm4{%k1}
	vpshldw	$0x23, %xmm7, %xmm0, %xmm1{%k2}{z}
	vpshldw	$0x42, (%eax), %xmm4, %xmm5
	vpshldw	$0x42, 0x23(%eax), %xmm4, %xmm5{%k3}
	vpshldw	$0x42, 0x23(%ebx, %ecx, 4), %xmm4, %xmm5{%k4}{z}

	vpshldw	$0x23, %ymm0, %ymm1, %ymm2
	vpshldw	$0x23, %ymm2, %ymm3, %ymm4{%k1}
	vpshldw	$0x23, %ymm7, %ymm0, %ymm1{%k2}{z}
	vpshldw	$0x42, (%eax), %ymm4, %ymm5
	vpshldw	$0x42, 0x23(%eax), %ymm4, %ymm5{%k3}
	vpshldw	$0x42, 0x23(%ebx, %ecx, 4), %ymm4, %ymm5{%k4}{z}

	vpshldw	$0x23, %zmm0, %zmm1, %zmm2
	vpshldw	$0x23, %zmm2, %zmm3, %zmm4{%k1}
	vpshldw	$0x23, %zmm7, %zmm0, %zmm1{%k2}{z}
	vpshldw	$0x42, (%eax), %zmm4, %zmm5
	vpshldw	$0x42, 0x23(%eax), %zmm4, %zmm5{%k3}
	vpshldw	$0x42, 0x23(%ebx, %ecx, 4), %zmm4, %zmm5{%k4}{z}

	vpshldd	$0x23, %xmm0, %xmm1, %xmm2
	vpshldd	$0x23, %xmm2, %xmm3, %xmm4{%k1}
	vpshldd	$0x23, %xmm7, %xmm0, %xmm1{%k2}{z}
	vpshldd	$0x42, (%eax), %xmm4, %xmm5
	vpshldd	$0x42, 0x23(%eax), %xmm4, %xmm5{%k3}
	vpshldd	$0x42, 0x23(%ebx, %ecx, 4), %xmm4, %xmm5{%k4}{z}
	vpshldd	$0x42, (%edx){1to4}, %xmm4, %xmm5
	vpshldd	$0x42, 0x72(%edx){1to4}, %xmm4, %xmm5{%k5}

	vpshldd	$0x23, %ymm0, %ymm1, %ymm2
	vpshldd	$0x23, %ymm2, %ymm3, %ymm4{%k1}
	vpshldd	$0x23, %ymm7, %ymm0, %ymm1{%k2}{z}
	vpshldd	$0x42, (%eax), %ymm4, %ymm5
	vpshldd	$0x42, 0x23(%eax), %ymm4, %ymm5{%k3}
	vpshldd	$0x42, 0x23(%ebx, %ecx, 4), %ymm4, %ymm5{%k4}{z}
	vpshldd	$0x42, (%edx){1to8}, %ymm4, %ymm5
	vpshldd	$0x42, 0x72(%edx){1to8}, %ymm4, %ymm5{%k5}

	vpshldd	$0x23, %zmm0, %zmm1, %zmm2
	vpshldd	$0x23, %zmm2, %zmm3, %zmm4{%k1}
	vpshldd	$0x23, %zmm7, %zmm0, %zmm1{%k2}{z}
	vpshldd	$0x42, (%eax), %zmm4, %zmm5
	vpshldd	$0x42, 0x23(%eax), %zmm4, %zmm5{%k3}
	vpshldd	$0x42, 0x23(%ebx, %ecx, 4), %zmm4, %zmm5{%k4}{z}
	vpshldd	$0x42, (%edx){1to16}, %zmm4, %zmm5
	vpshldd	$0x42, 0x72(%edx){1to16}, %zmm4, %zmm5{%k5}

	vpshldq	$0x23, %xmm0, %xmm1, %xmm2
	vpshldq	$0x23, %xmm2, %xmm3, %xmm4{%k1}
	vpshldq	$0x23, %xmm7, %xmm0, %xmm1{%k2}{z}
	vpshldq	$0x42, (%eax), %xmm4, %xmm5
	vpshldq	$0x42, 0x23(%eax), %xmm4, %xmm5{%k3}
	vpshldq	$0x42, 0x23(%ebx, %ecx, 4), %xmm4, %xmm5{%k4}{z}
	vpshldq	$0x42, (%edx){1to2}, %xmm4, %xmm5
	vpshldq	$0x42, 0x72(%edx){1to2}, %xmm4, %xmm5{%k5}

	vpshldq	$0x23, %ymm0, %ymm1, %ymm2
	vpshldq	$0x23, %ymm2, %ymm3, %ymm4{%k1}
	vpshldq	$0x23, %ymm7, %ymm0, %ymm1{%k2}{z}
	vpshldq	$0x42, (%eax), %ymm4, %ymm5
	vpshldq	$0x42, 0x23(%eax), %ymm4, %ymm5{%k3}
	vpshldq	$0x42, 0x23(%ebx, %ecx, 4), %ymm4, %ymm5{%k4}{z}
	vpshldq	$0x42, (%edx){1to4}, %ymm4, %ymm5
	vpshldq	$0x42, 0x72(%edx){1to4}, %ymm4, %ymm5{%k5}

	vpshldq	$0x23, %zmm0, %zmm1, %zmm2
	vpshldq	$0x23, %zmm2, %zmm3, %zmm4{%k1}
	vpshldq	$0x23, %zmm7, %zmm0, %zmm1{%k2}{z}
	vpshldq	$0x42, (%eax), %zmm4, %zmm5
	vpshldq	$0x42, 0x23(%eax), %zmm4, %zmm5{%k3}
	vpshldq	$0x42, 0x23(%ebx, %ecx, 4), %zmm4, %zmm5{%k4}{z}
	vpshldq	$0x42, (%edx){1to8}, %zmm4, %zmm5
	vpshldq	$0x42, 0x72(%edx){1to8}, %zmm4, %zmm5{%k5}

	vpshrdw	$0x23, %xmm0, %xmm1, %xmm2
	vpshrdw	$0x23, %xmm2, %xmm3, %xmm4{%k1}
	vpshrdw	$0x23, %xmm7, %xmm0, %xmm1{%k2}{z}
	vpshrdw	$0x42, (%eax), %xmm4, %xmm5
	vpshrdw	$0x42, 0x23(%eax), %xmm4, %xmm5{%k3}
	vpshrdw	$0x42, 0x23(%ebx, %ecx, 4), %xmm4, %xmm5{%k4}{z}

	vpshrdw	$0x23, %ymm0, %ymm1, %ymm2
	vpshrdw	$0x23, %ymm2, %ymm3, %ymm4{%k1}
	vpshrdw	$0x23, %ymm7, %ymm0, %ymm1{%k2}{z}
	vpshrdw	$0x42, (%eax), %ymm4, %ymm5
	vpshrdw	$0x42, 0x23(%eax), %ymm4, %ymm5{%k3}
	vpshrdw	$0x42, 0x23(%ebx, %ecx, 4), %ymm4, %ymm5{%k4}{z}

	vpshrdw	$0x23, %zmm0, %zmm1, %zmm2
	vpshrdw	$0x23, %zmm2, %zmm3, %zmm4{%k1}
	vpshrdw	$0x23, %zmm7, %zmm0, %zmm1{%k2}{z}
	vpshrdw	$0x42, (%eax), %zmm4, %zmm5
	vpshrdw	$0x42, 0x23(%eax), %zmm4, %zmm5{%k3}
	vpshrdw	$0x42, 0x23(%ebx, %ecx, 4), %zmm4, %zmm5{%k4}{z}

	vpshrdd	$0x23, %xmm0, %xmm1, %xmm2
	vpshrdd	$0x23, %xmm2, %xmm3, %xmm4{%k1}
	vpshrdd	$0x23, %xmm7, %xmm0, %xmm1{%k2}{z}
	vpshrdd	$0x42, (%eax), %xmm4, %xmm5
	vpshrdd	$0x42, 0x23(%eax), %xmm4, %xmm5{%k3}
	vpshrdd	$0x42, 0x23(%ebx, %ecx, 4), %xmm4, %xmm5{%k4}{z}
	vpshrdd	$0x42, (%edx){1to4}, %xmm4, %xmm5
	vpshrdd	$0x42, 0x72(%edx){1to4}, %xmm4, %xmm5{%k5}

	vpshrdd	$0x23, %ymm0, %ymm1, %ymm2
	vpshrdd	$0x23, %ymm2, %ymm3, %ymm4{%k1}
	vpshrdd	$0x23, %ymm7, %ymm0, %ymm1{%k2}{z}
	vpshrdd	$0x42, (%eax), %ymm4, %ymm5
	vpshrdd	$0x42, 0x23(%eax), %ymm4, %ymm5{%k3}
	vpshrdd	$0x42, 0x23(%ebx, %ecx, 4), %ymm4, %ymm5{%k4}{z}
	vpshrdd	$0x42, (%edx){1to8}, %ymm4, %ymm5
	vpshrdd	$0x42, 0x72(%edx){1to8}, %ymm4, %ymm5{%k5}

	vpshrdd	$0x23, %zmm0, %zmm1, %zmm2
	vpshrdd	$0x23, %zmm2, %zmm3, %zmm4{%k1}
	vpshrdd	$0x23, %zmm7, %zmm0, %zmm1{%k2}{z}
	vpshrdd	$0x42, (%eax), %zmm4, %zmm5
	vpshrdd	$0x42, 0x23(%eax), %zmm4, %zmm5{%k3}
	vpshrdd	$0x42, 0x23(%ebx, %ecx, 4), %zmm4, %zmm5{%k4}{z}
	vpshrdd	$0x42, (%edx){1to16}, %zmm4, %zmm5
	vpshrdd	$0x42, 0x72(%edx){1to16}, %zmm4, %zmm5{%k5}

	vpshrdq	$0x23, %xmm0, %xmm1, %xmm2
	vpshrdq	$0x23, %xmm2, %xmm3, %xmm4{%k1}
	vpshrdq	$0x23, %xmm7, %xmm0, %xmm1{%k2}{z}
	vpshrdq	$0x42, (%eax), %xmm4, %xmm5
	vpshrdq	$0x42, 0x23(%eax), %xmm4, %xmm5{%k3}
	vpshrdq	$0x42, 0x23(%ebx, %ecx, 4), %xmm4, %xmm5{%k4}{z}
	vpshrdq	$0x42, (%edx){1to2}, %xmm4, %xmm5
	vpshrdq	$0x42, 0x72(%edx){1to2}, %xmm4, %xmm5{%k5}

	vpshrdq	$0x23, %ymm0, %ymm1, %ymm2
	vpshrdq	$0x23, %ymm2, %ymm3, %ymm4{%k1}
	vpshrdq	$0x23, %ymm7, %ymm0, %ymm1{%k2}{z}
	vpshrdq	$0x42, (%eax), %ymm4, %ymm5
	vpshrdq	$0x42, 0x23(%eax), %ymm4, %ymm5{%k3}
	vpshrdq	$0x42, 0x23(%ebx, %ecx, 4), %ymm4, %ymm5{%k4}{z}
	vpshrdq	$0x42, (%edx){1to4}, %ymm4, %ymm5
	vpshrdq	$0x42, 0x72(%edx){1to4}, %ymm4, %ymm5{%k5}

	vpshrdq	$0x23, %zmm0, %zmm1, %zmm2
	vpshrdq	$0x23, %zmm2, %zmm3, %zmm4{%k1}
	vpshrdq	$0x23, %zmm7, %zmm0, %zmm1{%k2}{z}
	vpshrdq	$0x42, (%eax), %zmm4, %zmm5
	vpshrdq	$0x42, 0x23(%eax), %zmm4, %zmm5{%k3}
	vpshrdq	$0x42, 0x23(%ebx, %ecx, 4), %zmm4, %zmm5{%k4}{z}
	vpshrdq	$0x42, (%edx){1to8}, %zmm4, %zmm5
	vpshrdq	$0x42, 0x72(%edx){1to8}, %zmm4, %zmm5{%k5}

	vpcompressb	%xmm0, %xmm1
	vpcompressb	%xmm1, %xmm2{%k1}
	vpcompressb	%xmm2, %xmm3{%k2}{z}
	vpcompressb	%xmm4, (%eax)
	vpcompressb	%xmm5, (%eax){%k3}
	vpcompressb	%xmm6, 0x23(%eax)
	vpcompressb	%xmm6, 0x24(%eax)
	vpcompressb	%xmm7, 0x42(%eax){%k3}

	vpcompressb	%ymm0, %ymm1
	vpcompressb	%ymm1, %ymm2{%k1}
	vpcompressb	%ymm2, %ymm3{%k2}{z}
	vpcompressb	%ymm4, (%eax)
	vpcompressb	%ymm5, (%eax){%k3}
	vpcompressb	%ymm6, 0x23(%eax)
	vpcompressb	%ymm6, 0x24(%eax)
	vpcompressb	%ymm7, 0x42(%eax){%k3}

	vpcompressb	%zmm0, %zmm1
	vpcompressb	%zmm1, %zmm2{%k1}
	vpcompressb	%zmm2, %zmm3{%k2}{z}
	vpcompressb	%zmm4, (%eax)
	vpcompressb	%zmm5, (%eax){%k3}
	vpcompressb	%zmm6, 0x23(%eax)
	vpcompressb	%zmm6, 0x24(%eax)
	vpcompressb	%zmm7, 0x42(%eax){%k3}

	vpcompressw	%xmm0, %xmm1
	vpcompressw	%xmm1, %xmm2{%k1}
	vpcompressw	%xmm2, %xmm3{%k2}{z}
	vpcompressw	%xmm4, (%eax)
	vpcompressw	%xmm5, (%eax){%k3}
	vpcompressw	%xmm6, 0x23(%eax)
	vpcompressw	%xmm6, 0x24(%eax)
	vpcompressw	%xmm7, 0x42(%eax){%k3}

	vpcompressw	%ymm0, %ymm1
	vpcompressw	%ymm1, %ymm2{%k1}
	vpcompressw	%ymm2, %ymm3{%k2}{z}
	vpcompressw	%ymm4, (%eax)
	vpcompressw	%ymm5, (%eax){%k3}
	vpcompressw	%ymm6, 0x23(%eax)
	vpcompressw	%ymm6, 0x24(%eax)
	vpcompressw	%ymm7, 0x42(%eax){%k3}

	vpcompressw	%zmm0, %zmm1
	vpcompressw	%zmm1, %zmm2{%k1}
	vpcompressw	%zmm2, %zmm3{%k2}{z}
	vpcompressw	%zmm4, (%eax)
	vpcompressw	%zmm5, (%eax){%k3}
	vpcompressw	%zmm6, 0x23(%eax)
	vpcompressw	%zmm6, 0x24(%eax)
	vpcompressw	%zmm7, 0x42(%eax){%k3}

	vpexpandb	%xmm0, %xmm1
	vpexpandb	%xmm1, %xmm2{%k1}
	vpexpandb	%xmm2, %xmm3{%k2}{z}
	vpexpandb	(%eax), %xmm4
	vpexpandb	(%eax), %xmm5{%k3}
	vpexpandb	0x23(%eax), %xmm6
	vpexpandb	0x24(%eax), %xmm6
	vpexpandb	0x42(%eax), %xmm7{%k3}{z}

	vpexpandb	%ymm0, %ymm1
	vpexpandb	%ymm1, %ymm2{%k1}
	vpexpandb	%ymm2, %ymm3{%k2}{z}
	vpexpandb	(%eax), %ymm4
	vpexpandb	(%eax), %ymm5{%k3}
	vpexpandb	0x23(%eax), %ymm6
	vpexpandb	0x24(%eax), %ymm6
	vpexpandb	0x42(%eax), %ymm7{%k3}{z}

	vpexpandb	%zmm0, %zmm1
	vpexpandb	%zmm1, %zmm2{%k1}
	vpexpandb	%zmm2, %zmm3{%k2}{z}
	vpexpandb	(%eax), %zmm4
	vpexpandb	(%eax), %zmm5{%k3}
	vpexpandb	0x23(%eax), %zmm6
	vpexpandb	0x24(%eax), %zmm6
	vpexpandb	0x42(%eax), %zmm7{%k3}{z}

	vpshldvw	%xmm0, %xmm1, %xmm2
	vpshldvw	%xmm2, %xmm3, %xmm4{%k1}
	vpshldvw	%xmm7, %xmm0, %xmm1{%k2}{z}
	vpshldvw	(%eax), %xmm4, %xmm5
	vpshldvw	0x23(%eax), %xmm4, %xmm5{%k3}
	vpshldvw	0x23(%ebx, %ecx, 4), %xmm4, %xmm5{%k4}{z}

	vpshldvw	%ymm0, %ymm1, %ymm2
	vpshldvw	%ymm2, %ymm3, %ymm4{%k1}
	vpshldvw	%ymm7, %ymm0, %ymm1{%k2}{z}
	vpshldvw	(%eax), %ymm4, %ymm5
	vpshldvw	0x23(%eax), %ymm4, %ymm5{%k3}
	vpshldvw	0x23(%ebx, %ecx, 4), %ymm4, %ymm5{%k4}{z}

	vpshldvw	%zmm0, %zmm1, %zmm2
	vpshldvw	%zmm2, %zmm3, %zmm4{%k1}
	vpshldvw	%zmm7, %zmm0, %zmm1{%k2}{z}
	vpshldvw	(%eax), %zmm4, %zmm5
	vpshldvw	0x23(%eax), %zmm4, %zmm5{%k3}
	vpshldvw	0x23(%ebx, %ecx, 4), %zmm4, %zmm5{%k4}{z}

	vpshldvd	%xmm0, %xmm1, %xmm2
	vpshldvd	%xmm2, %xmm3, %xmm4{%k1}
	vpshldvd	%xmm7, %xmm0, %xmm1{%k2}{z}
	vpshldvd	(%eax), %xmm4, %xmm5
	vpshldvd	0x23(%eax), %xmm4, %xmm5{%k3}
	vpshldvd	0x23(%ebx, %ecx, 4), %xmm4, %xmm5{%k4}{z}
	vpshldvd	(%edx){1to4}, %xmm4, %xmm5
	vpshldvd	0x72(%edx){1to4}, %xmm4, %xmm5{%k5}

	vpshldvd	%ymm0, %ymm1, %ymm2
	vpshldvd	%ymm2, %ymm3, %ymm4{%k1}
	vpshldvd	%ymm7, %ymm0, %ymm1{%k2}{z}
	vpshldvd	(%eax), %ymm4, %ymm5
	vpshldvd	0x23(%eax), %ymm4, %ymm5{%k3}
	vpshldvd	0x23(%ebx, %ecx, 4), %ymm4, %ymm5{%k4}{z}
	vpshldvd	(%edx){1to8}, %ymm4, %ymm5
	vpshldvd	0x72(%edx){1to8}, %ymm4, %ymm5{%k5}

	vpshldvd	%zmm0, %zmm1, %zmm2
	vpshldvd	%zmm2, %zmm3, %zmm4{%k1}
	vpshldvd	%zmm7, %zmm0, %zmm1{%k2}{z}
	vpshldvd	(%eax), %zmm4, %zmm5
	vpshldvd	0x23(%eax), %zmm4, %zmm5{%k3}
	vpshldvd	0x23(%ebx, %ecx, 4), %zmm4, %zmm5{%k4}{z}
	vpshldvd	(%edx){1to16}, %zmm4, %zmm5
	vpshldvd	0x72(%edx){1to16}, %zmm4, %zmm5{%k5}

	vpshldvq	%xmm0, %xmm1, %xmm2
	vpshldvq	%xmm2, %xmm3, %xmm4{%k1}
	vpshldvq	%xmm7, %xmm0, %xmm1{%k2}{z}
	vpshldvq	(%eax), %xmm4, %xmm5
	vpshldvq	0x23(%eax), %xmm4, %xmm5{%k3}
	vpshldvq	0x23(%ebx, %ecx, 4), %xmm4, %xmm5{%k4}{z}
	vpshldvq	(%edx){1to2}, %xmm4, %xmm5
	vpshldvq	0x72(%edx){1to2}, %xmm4, %xmm5{%k5}

	vpshldvq	%ymm0, %ymm1, %ymm2
	vpshldvq	%ymm2, %ymm3, %ymm4{%k1}
	vpshldvq	%ymm7, %ymm0, %ymm1{%k2}{z}
	vpshldvq	(%eax), %ymm4, %ymm5
	vpshldvq	0x23(%eax), %ymm4, %ymm5{%k3}
	vpshldvq	0x23(%ebx, %ecx, 4), %ymm4, %ymm5{%k4}{z}
	vpshldvq	(%edx){1to4}, %ymm4, %ymm5
	vpshldvq	0x72(%edx){1to4}, %ymm4, %ymm5{%k5}

	vpshldvq	%zmm0, %zmm1, %zmm2
	vpshldvq	%zmm2, %zmm3, %zmm4{%k1}
	vpshldvq	%zmm7, %zmm0, %zmm1{%k2}{z}
	vpshldvq	(%eax), %zmm4, %zmm5
	vpshldvq	0x23(%eax), %zmm4, %zmm5{%k3}
	vpshldvq	0x23(%ebx, %ecx, 4), %zmm4, %zmm5{%k4}{z}
	vpshldvq	(%edx){1to8}, %zmm4, %zmm5
	vpshldvq	0x72(%edx){1to8}, %zmm4, %zmm5{%k5}

	vpshrdvw	%xmm0, %xmm1, %xmm2
	vpshrdvw	%xmm2, %xmm3, %xmm4{%k1}
	vpshrdvw	%xmm7, %xmm0, %xmm1{%k2}{z}
	vpshrdvw	(%eax), %xmm4, %xmm5
	vpshrdvw	0x23(%eax), %xmm4, %xmm5{%k3}
	vpshrdvw	0x23(%ebx, %ecx, 4), %xmm4, %xmm5{%k4}{z}

	vpshrdvw	%ymm0, %ymm1, %ymm2
	vpshrdvw	%ymm2, %ymm3, %ymm4{%k1}
	vpshrdvw	%ymm7, %ymm0, %ymm1{%k2}{z}
	vpshrdvw	(%eax), %ymm4, %ymm5
	vpshrdvw	0x23(%eax), %ymm4, %ymm5{%k3}
	vpshrdvw	0x23(%ebx, %ecx, 4), %ymm4, %ymm5{%k4}{z}

	vpshrdvw	%zmm0, %zmm1, %zmm2
	vpshrdvw	%zmm2, %zmm3, %zmm4{%k1}
	vpshrdvw	%zmm7, %zmm0, %zmm1{%k2}{z}
	vpshrdvw	(%eax), %zmm4, %zmm5
	vpshrdvw	0x23(%eax), %zmm4, %zmm5{%k3}
	vpshrdvw	0x23(%ebx, %ecx, 4), %zmm4, %zmm5{%k4}{z}

	vpshrdvd	%xmm0, %xmm1, %xmm2
	vpshrdvd	%xmm2, %xmm3, %xmm4{%k1}
	vpshrdvd	%xmm7, %xmm0, %xmm1{%k2}{z}
	vpshrdvd	(%eax), %xmm4, %xmm5
	vpshrdvd	0x23(%eax), %xmm4, %xmm5{%k3}
	vpshrdvd	0x23(%ebx, %ecx, 4), %xmm4, %xmm5{%k4}{z}
	vpshrdvd	(%edx){1to4}, %xmm4, %xmm5
	vpshrdvd	0x72(%edx){1to4}, %xmm4, %xmm5{%k5}

	vpshrdvd	%ymm0, %ymm1, %ymm2
	vpshrdvd	%ymm2, %ymm3, %ymm4{%k1}
	vpshrdvd	%ymm7, %ymm0, %ymm1{%k2}{z}
	vpshrdvd	(%eax), %ymm4, %ymm5
	vpshrdvd	0x23(%eax), %ymm4, %ymm5{%k3}
	vpshrdvd	0x23(%ebx, %ecx, 4), %ymm4, %ymm5{%k4}{z}
	vpshrdvd	(%edx){1to8}, %ymm4, %ymm5
	vpshrdvd	0x72(%edx){1to8}, %ymm4, %ymm5{%k5}

	vpshrdvd	%zmm0, %zmm1, %zmm2
	vpshrdvd	%zmm2, %zmm3, %zmm4{%k1}
	vpshrdvd	%zmm7, %zmm0, %zmm1{%k2}{z}
	vpshrdvd	(%eax), %zmm4, %zmm5
	vpshrdvd	0x23(%eax), %zmm4, %zmm5{%k3}
	vpshrdvd	0x23(%ebx, %ecx, 4), %zmm4, %zmm5{%k4}{z}
	vpshrdvd	(%edx){1to16}, %zmm4, %zmm5
	vpshrdvd	0x72(%edx){1to16}, %zmm4, %zmm5{%k5}

	vpshrdvq	%xmm0, %xmm1, %xmm2
	vpshrdvq	%xmm2, %xmm3, %xmm4{%k1}
	vpshrdvq	%xmm7, %xmm0, %xmm1{%k2}{z}
	vpshrdvq	(%eax), %xmm4, %xmm5
	vpshrdvq	0x23(%eax), %xmm4, %xmm5{%k3}
	vpshrdvq	0x23(%ebx, %ecx, 4), %xmm4, %xmm5{%k4}{z}
	vpshrdvq	(%edx){1to2}, %xmm4, %xmm5
	vpshrdvq	0x72(%edx){1to2}, %xmm4, %xmm5{%k5}

	vpshrdvq	%ymm0, %ymm1, %ymm2
	vpshrdvq	%ymm2, %ymm3, %ymm4{%k1}
	vpshrdvq	%ymm7, %ymm0, %ymm1{%k2}{z}
	vpshrdvq	(%eax), %ymm4, %ymm5
	vpshrdvq	0x23(%eax), %ymm4, %ymm5{%k3}
	vpshrdvq	0x23(%ebx, %ecx, 4), %ymm4, %ymm5{%k4}{z}
	vpshrdvq	(%edx){1to4}, %ymm4, %ymm5
	vpshrdvq	0x80(%edx){1to4}, %ymm4, %ymm5{%k5}

	vpshrdvq	%zmm0, %zmm1, %zmm2
	vpshrdvq	%zmm2, %zmm3, %zmm4{%k1}
	vpshrdvq	%zmm7, %zmm0, %zmm1{%k2}{z}
	vpshrdvq	(%eax), %zmm4, %zmm5
	vpshrdvq	0x23(%eax), %zmm4, %zmm5{%k3}
	vpshrdvq	0x23(%ebx, %ecx, 4), %zmm4, %zmm5{%k4}{z}
	vpshrdvq	(%edx){1to8}, %zmm4, %zmm5
	vpshrdvq	0x72(%edx){1to8}, %zmm4, %zmm5{%k5}
.size libdis_test, [.-libdis_test]
