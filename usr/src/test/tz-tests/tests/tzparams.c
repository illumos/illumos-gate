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
 * This program prints a few of the internal parameters that we're using for the
 * sizing of various Timezone related databases so that scripts don't have to
 * hardcode the constants. This outputs data in a shell-compatible way.
 */

#include <stdio.h>
#include <tzfile.h>

int
main(void)
{
	(void) printf("TZ_MAX_TIMES=%u\n", TZ_MAX_TIMES);
	(void) printf("TZ_MAX_CHARS=%u\n", TZ_MAX_CHARS);
	return (0);
}
