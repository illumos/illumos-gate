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
 * This is a dummy library that basically ensures we have yet another thing with
 * CTF and DWARF data when we're testing core dumps.
 */

#include <err.h>
#include <inttypes.h>
#include <stdlib.h>

const char *message_in_a_bottle = "Here's something that hopefully is rodata";

int
which_ff(uint32_t a, uint32_t b)
{
	if (a == 6 && b == 7) {
		warnx("some debates are best left to forums");
		abort();
	}

	return (0);
}
