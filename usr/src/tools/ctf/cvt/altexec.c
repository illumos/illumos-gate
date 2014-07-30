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
 * Copyright (c) 2015, Joyent, Inc.
 */

/*
 * Alternate execution engine for CTF tools
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ctftools.h"

void
ctf_altexec(const char *env, int argc, char **argv)
{
	const char *alt;
	char *altexec;

	alt = getenv(env);
	if (alt == NULL || *alt == '\0')
		return;

	altexec = strdup(alt);
	if (altexec == NULL)
		terminate("failed to allocate memory for altexec\n");

	if (unsetenv(env) != 0)
		aborterr("failed to remove %s from environment", env);

	(void) execv(altexec, argv);
	terminate("failed to altexec %s", altexec);
}
