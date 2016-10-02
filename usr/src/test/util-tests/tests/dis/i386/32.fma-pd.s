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
 * Test FMA3 -PD related instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	vfmadd132pd	%xmm0, %xmm1, %xmm2
	vfmadd132pd	(%eax), %xmm1, %xmm2
	vfmadd132pd	%ymm0, %ymm1, %ymm2
	vfmadd132pd	(%eax), %ymm1, %ymm2
	vfmadd213pd	%xmm0, %xmm1, %xmm2
	vfmadd213pd	(%eax), %xmm1, %xmm2
	vfmadd213pd	%ymm0, %ymm1, %ymm2
	vfmadd213pd	(%eax), %ymm1, %ymm2
	vfmadd231pd	%xmm0, %xmm1, %xmm2
	vfmadd231pd	(%eax), %xmm1, %xmm2
	vfmadd231pd	%ymm0, %ymm1, %ymm2
	vfmadd231pd	(%eax), %ymm1, %ymm2
	vfmaddsub132pd	%xmm0, %xmm1, %xmm2
	vfmaddsub132pd	(%eax), %xmm1, %xmm2
	vfmaddsub132pd	%ymm0, %ymm1, %ymm2
	vfmaddsub132pd	(%eax), %ymm1, %ymm2
	vfmaddsub213pd	%xmm0, %xmm1, %xmm2
	vfmaddsub213pd	(%eax), %xmm1, %xmm2
	vfmaddsub213pd	%ymm0, %ymm1, %ymm2
	vfmaddsub213pd	(%eax), %ymm1, %ymm2
	vfmaddsub231pd	%xmm0, %xmm1, %xmm2
	vfmaddsub231pd	(%eax), %xmm1, %xmm2
	vfmaddsub231pd	%ymm0, %ymm1, %ymm2
	vfmaddsub231pd	(%eax), %ymm1, %ymm2
	vfmsub132pd	%xmm0, %xmm1, %xmm2
	vfmsub132pd	(%eax), %xmm1, %xmm2
	vfmsub132pd	%ymm0, %ymm1, %ymm2
	vfmsub132pd	(%eax), %ymm1, %ymm2
	vfmsub213pd	%xmm0, %xmm1, %xmm2
	vfmsub213pd	(%eax), %xmm1, %xmm2
	vfmsub213pd	%ymm0, %ymm1, %ymm2
	vfmsub213pd	(%eax), %ymm1, %ymm2
	vfmsub231pd	%xmm0, %xmm1, %xmm2
	vfmsub231pd	(%eax), %xmm1, %xmm2
	vfmsub231pd	%ymm0, %ymm1, %ymm2
	vfmsub231pd	(%eax), %ymm1, %ymm2
	vfmsubadd132pd	%xmm0, %xmm1, %xmm2
	vfmsubadd132pd	(%eax), %xmm1, %xmm2
	vfmsubadd132pd	%ymm0, %ymm1, %ymm2
	vfmsubadd132pd	(%eax), %ymm1, %ymm2
	vfmsubadd213pd	%xmm0, %xmm1, %xmm2
	vfmsubadd213pd	(%eax), %xmm1, %xmm2
	vfmsubadd213pd	%ymm0, %ymm1, %ymm2
	vfmsubadd213pd	(%eax), %ymm1, %ymm2
	vfmsubadd231pd	%xmm0, %xmm1, %xmm2
	vfmsubadd231pd	(%eax), %xmm1, %xmm2
	vfmsubadd231pd	%ymm0, %ymm1, %ymm2
	vfmsubadd231pd	(%eax), %ymm1, %ymm2
	vfnmadd132pd	%xmm0, %xmm1, %xmm2
	vfnmadd132pd	(%eax), %xmm1, %xmm2
	vfnmadd132pd	%ymm0, %ymm1, %ymm2
	vfnmadd132pd	(%eax), %ymm1, %ymm2
	vfnmadd213pd	%xmm0, %xmm1, %xmm2
	vfnmadd213pd	(%eax), %xmm1, %xmm2
	vfnmadd213pd	%ymm0, %ymm1, %ymm2
	vfnmadd213pd	(%eax), %ymm1, %ymm2
	vfnmadd231pd	%xmm0, %xmm1, %xmm2
	vfnmadd231pd	(%eax), %xmm1, %xmm2
	vfnmadd231pd	%ymm0, %ymm1, %ymm2
	vfnmadd231pd	(%eax), %ymm1, %ymm2
	vfnmsub132pd	%xmm0, %xmm1, %xmm2
	vfnmsub132pd	(%eax), %xmm1, %xmm2
	vfnmsub132pd	%ymm0, %ymm1, %ymm2
	vfnmsub132pd	(%eax), %ymm1, %ymm2
	vfnmsub213pd	%xmm0, %xmm1, %xmm2
	vfnmsub213pd	(%eax), %xmm1, %xmm2
	vfnmsub213pd	%ymm0, %ymm1, %ymm2
	vfnmsub213pd	(%eax), %ymm1, %ymm2
	vfnmsub231pd	%xmm0, %xmm1, %xmm2
	vfnmsub231pd	(%eax), %xmm1, %xmm2
	vfnmsub231pd	%ymm0, %ymm1, %ymm2
	vfnmsub231pd	(%eax), %ymm1, %ymm2
.size libdis_test, [.-libdis_test]
