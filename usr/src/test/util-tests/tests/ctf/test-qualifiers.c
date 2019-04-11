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
 * Copyright 2019, Joyent, Inc.
 */

/*
 * Make sure that we're encoding qualifiers correctly.
 */

const union const_union {
	int i;
} const_union_array[5];

const struct const_struct {
	int i;
} const_struct_array[7];

volatile struct volatile_struct {
	int i;
} volatile_struct_array[9];

const int c_int_array[11];
const volatile int cv_int_array[13];
volatile const int vc_int_array[15];
volatile int const vc_int_array2[17];

const int c_2d_array[4][2];
const volatile int cv_3d_array[3][2][1];

const int *ptr_to_const_int;
int * const const_ptr_to_int;
const int * const const_ptr_to_const_int;
