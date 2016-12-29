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
 * Test ADX related instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	vfmadd132sd	%xmm0, %xmm1, %xmm2
	vfmadd132sd	(%rax), %xmm1, %xmm2
	vfmadd213sd	%xmm0, %xmm1, %xmm2
	vfmadd213sd	(%rax), %xmm1, %xmm2
	vfmadd231sd	%xmm0, %xmm1, %xmm2
	vfmadd231sd	(%rax), %xmm1, %xmm2
	vfmsub132sd	%xmm0, %xmm1, %xmm2
	vfmsub132sd	(%rax), %xmm1, %xmm2
	vfmsub213sd	%xmm0, %xmm1, %xmm2
	vfmsub213sd	(%rax), %xmm1, %xmm2
	vfmsub231sd	%xmm0, %xmm1, %xmm2
	vfmsub231sd	(%rax), %xmm1, %xmm2
	vfnmadd132sd	%xmm0, %xmm1, %xmm2
	vfnmadd132sd	(%rax), %xmm1, %xmm2
	vfnmadd213sd	%xmm0, %xmm1, %xmm2
	vfnmadd213sd	(%rax), %xmm1, %xmm2
	vfnmadd231sd	%xmm0, %xmm1, %xmm2
	vfnmadd231sd	(%rax), %xmm1, %xmm2
	vfnmsub132sd	%xmm0, %xmm1, %xmm2
	vfnmsub132sd	(%rax), %xmm1, %xmm2
	vfnmsub213sd	%xmm0, %xmm1, %xmm2
	vfnmsub213sd	(%rax), %xmm1, %xmm2
	vfnmsub231sd	%xmm0, %xmm1, %xmm2
	vfnmsub231sd	(%rax), %xmm1, %xmm2
.size libdis_test, [.-libdis_test]
