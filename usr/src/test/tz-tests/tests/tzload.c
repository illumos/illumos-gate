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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * The purpose of this program is to force a given timezone to be loaded so the
 * internal libc state can be printed with mdb.
 */

#include <time.h>
#include <string.h>

#pragma weak mdb_hook
void
mdb_hook(void)
{
}

int
main(void)
{
	tzset();
	mdb_hook();
	return (0);
}
