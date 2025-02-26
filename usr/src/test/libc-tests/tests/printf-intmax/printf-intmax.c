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
 * Copyright 2025 Hans Rosenfeld
 */

/*
 * The 32bit libc contains special variants of all printf functions
 * for a strict C89 environment where intmax_t is only 32 bits wide.
 * These handle intmax_t arguments ('j' length modifier) accordingly.
 *
 * Since our feature-tests header assumes that if __GNUC__ is defined,
 * then we also always have a long long type, so it is used for intmax_t
 * when compiling with gcc even with -std=c89 -pedantic. To work around
 * this, allowing this test to actually do what it needs to do based on
 * how it is compiled, we undef __GNUC__ here.
 */

#undef __GNUC__

#include <stdio.h>

int
main(int argc, char **argv)
{
	printf("long long: %#llx\n", (long long)-1);
	printf("intmax_t: %#jx\n", (long long)-1);

	return (0);
}
