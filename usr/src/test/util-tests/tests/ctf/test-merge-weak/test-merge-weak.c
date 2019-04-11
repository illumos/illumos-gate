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

#include <stdlib.h>

#pragma weak mumble = _mumble
#pragma weak foo = _foo

int _foo = 5;

int
_mumble(void)
{
	return ((int)arc4random());
}

extern int mumble(void);

int
main(void)
{
	return (mumble());
};
