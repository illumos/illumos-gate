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

/*
 * Test the encoding of references to another type. Specifically the references
 * that we generally care about are things like:
 *
 * o pointers
 * o typedefs
 * o const
 * o volatile
 * o restrict
 */

int a;
typedef int test_int_t;
test_int_t aa;
const short b;
volatile float c;

int *d;
int **dd;
int ***ddd;
test_int_t *e;
const test_int_t *ce;
volatile test_int_t *ve;
volatile const test_int_t *cve;
int *const *f;
const char *const g;

typedef int *const * foo_t;
const volatile foo_t *cvh;
