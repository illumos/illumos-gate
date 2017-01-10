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
 * Copyright 2016 Joyent, Inc.
 */

/*
 * Test FMA3 -PS related instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	vfmadd132ps	%xmm0, %xmm1, %xmm2
	vfmadd132ps	(%eax), %xmm1, %xmm2
	vfmadd132ps	%ymm0, %ymm1, %ymm2
	vfmadd132ps	(%eax), %ymm1, %ymm2
	vfmadd213ps	%xmm0, %xmm1, %xmm2
	vfmadd213ps	(%eax), %xmm1, %xmm2
	vfmadd213ps	%ymm0, %ymm1, %ymm2
	vfmadd213ps	(%eax), %ymm1, %ymm2
	vfmadd231ps	%xmm0, %xmm1, %xmm2
	vfmadd231ps	(%eax), %xmm1, %xmm2
	vfmadd231ps	%ymm0, %ymm1, %ymm2
	vfmadd231ps	(%eax), %ymm1, %ymm2
	vfmaddsub132ps	%xmm0, %xmm1, %xmm2
	vfmaddsub132ps	(%eax), %xmm1, %xmm2
	vfmaddsub132ps	%ymm0, %ymm1, %ymm2
	vfmaddsub132ps	(%eax), %ymm1, %ymm2
	vfmaddsub213ps	%xmm0, %xmm1, %xmm2
	vfmaddsub213ps	(%eax), %xmm1, %xmm2
	vfmaddsub213ps	%ymm0, %ymm1, %ymm2
	vfmaddsub213ps	(%eax), %ymm1, %ymm2
	vfmaddsub231ps	%xmm0, %xmm1, %xmm2
	vfmaddsub231ps	(%eax), %xmm1, %xmm2
	vfmaddsub231ps	%ymm0, %ymm1, %ymm2
	vfmaddsub231ps	(%eax), %ymm1, %ymm2
	vfmsub132ps	%xmm0, %xmm1, %xmm2
	vfmsub132ps	(%eax), %xmm1, %xmm2
	vfmsub132ps	%ymm0, %ymm1, %ymm2
	vfmsub132ps	(%eax), %ymm1, %ymm2
	vfmsub213ps	%xmm0, %xmm1, %xmm2
	vfmsub213ps	(%eax), %xmm1, %xmm2
	vfmsub213ps	%ymm0, %ymm1, %ymm2
	vfmsub213ps	(%eax), %ymm1, %ymm2
	vfmsub231ps	%xmm0, %xmm1, %xmm2
	vfmsub231ps	(%eax), %xmm1, %xmm2
	vfmsub231ps	%ymm0, %ymm1, %ymm2
	vfmsub231ps	(%eax), %ymm1, %ymm2
	vfmsubadd132ps	%xmm0, %xmm1, %xmm2
	vfmsubadd132ps	(%eax), %xmm1, %xmm2
	vfmsubadd132ps	%ymm0, %ymm1, %ymm2
	vfmsubadd132ps	(%eax), %ymm1, %ymm2
	vfmsubadd213ps	%xmm0, %xmm1, %xmm2
	vfmsubadd213ps	(%eax), %xmm1, %xmm2
	vfmsubadd213ps	%ymm0, %ymm1, %ymm2
	vfmsubadd213ps	(%eax), %ymm1, %ymm2
	vfmsubadd231ps	%xmm0, %xmm1, %xmm2
	vfmsubadd231ps	(%eax), %xmm1, %xmm2
	vfmsubadd231ps	%ymm0, %ymm1, %ymm2
	vfmsubadd231ps	(%eax), %ymm1, %ymm2
	vfnmadd132ps	%xmm0, %xmm1, %xmm2
	vfnmadd132ps	(%eax), %xmm1, %xmm2
	vfnmadd132ps	%ymm0, %ymm1, %ymm2
	vfnmadd132ps	(%eax), %ymm1, %ymm2
	vfnmadd213ps	%xmm0, %xmm1, %xmm2
	vfnmadd213ps	(%eax), %xmm1, %xmm2
	vfnmadd213ps	%ymm0, %ymm1, %ymm2
	vfnmadd213ps	(%eax), %ymm1, %ymm2
	vfnmadd231ps	%xmm0, %xmm1, %xmm2
	vfnmadd231ps	(%eax), %xmm1, %xmm2
	vfnmadd231ps	%ymm0, %ymm1, %ymm2
	vfnmadd231ps	(%eax), %ymm1, %ymm2
	vfnmsub132ps	%xmm0, %xmm1, %xmm2
	vfnmsub132ps	(%eax), %xmm1, %xmm2
	vfnmsub132ps	%ymm0, %ymm1, %ymm2
	vfnmsub132ps	(%eax), %ymm1, %ymm2
	vfnmsub213ps	%xmm0, %xmm1, %xmm2
	vfnmsub213ps	(%eax), %xmm1, %xmm2
	vfnmsub213ps	%ymm0, %ymm1, %ymm2
	vfnmsub213ps	(%eax), %ymm1, %ymm2
	vfnmsub231ps	%xmm0, %xmm1, %xmm2
	vfnmsub231ps	(%eax), %xmm1, %xmm2
	vfnmsub231ps	%ymm0, %ymm1, %ymm2
	vfnmsub231ps	(%eax), %ymm1, %ymm2
.size libdis_test, [.-libdis_test]
