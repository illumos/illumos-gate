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

#include <stdlib.h>
#include <unistd.h>

int
main(void)
{
	pid_t pg = getpgid(0);
	pid_t sid = getsid(0);

	if (write(STDOUT_FILENO, &sid, sizeof (sid)) != sizeof (sid)) {
		return (EXIT_FAILURE);
	}

	if (write(STDOUT_FILENO, &pg, sizeof (pg)) != sizeof (pg)) {
		return (EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}
