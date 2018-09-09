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
 * Copyright (c) 2019, Joyent, Inc.
 */

#include <complex.h>

/*
 * Test floating point types. Unfortunately neither gcc nor clang support the
 * imaginary keyword which means that we cannot test it.
 */

float a;
double b;
long double c;
float complex d;
double complex e;
long double complex f;
