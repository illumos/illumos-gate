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
 * Copyright 2021 Oxide Computer Company
 */

/*
 * This C program has a few symbols whose goal it is to try and make sure mdb
 * prints instead of interpretting it as a number.
 */

#include <stdio.h>

const char *ffffabcde00 = "Am I a string?";
const char *ffffab_cde00 = "I am not a string";

int
_007(void)
{
	return (7);
}

int
main(void)
{
	printf("%s", ffffabcde00);
	return (_007());
}
