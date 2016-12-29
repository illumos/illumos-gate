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
	vfmadd132ss	%xmm0, %xmm1, %xmm2
	vfmadd132ss	(%eax), %xmm1, %xmm2
	vfmadd213ss	%xmm0, %xmm1, %xmm2
	vfmadd213ss	(%eax), %xmm1, %xmm2
	vfmadd231ss	%xmm0, %xmm1, %xmm2
	vfmadd231ss	(%eax), %xmm1, %xmm2
	vfmsub132ss	%xmm0, %xmm1, %xmm2
	vfmsub132ss	(%eax), %xmm1, %xmm2
	vfmsub213ss	%xmm0, %xmm1, %xmm2
	vfmsub213ss	(%eax), %xmm1, %xmm2
	vfmsub231ss	%xmm0, %xmm1, %xmm2
	vfmsub231ss	(%eax), %xmm1, %xmm2
	vfnmadd132ss	%xmm0, %xmm1, %xmm2
	vfnmadd132ss	(%eax), %xmm1, %xmm2
	vfnmadd213ss	%xmm0, %xmm1, %xmm2
	vfnmadd213ss	(%eax), %xmm1, %xmm2
	vfnmadd231ss	%xmm0, %xmm1, %xmm2
	vfnmadd231ss	(%eax), %xmm1, %xmm2
	vfnmsub132ss	%xmm0, %xmm1, %xmm2
	vfnmsub132ss	(%eax), %xmm1, %xmm2
	vfnmsub213ss	%xmm0, %xmm1, %xmm2
	vfnmsub213ss	(%eax), %xmm1, %xmm2
	vfnmsub231ss	%xmm0, %xmm1, %xmm2
	vfnmsub231ss	(%eax), %xmm1, %xmm2
.size libdis_test, [.-libdis_test]
