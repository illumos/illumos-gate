/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <sys/promif.h>

static char hostname[MAXHOSTNAMELEN] = "UNKNOWN";

/*
 * Get system hostname
 */
int
gethostname(char *name, int namelen)
{
	(void) strlcpy(name, hostname, MIN(namelen, MAXHOSTNAMELEN));
	return (0);
}

/*
 * Set system hostname
 */
int
sethostname(char *name, int namelen)
{
	(void) strlcpy(hostname, name, MIN(namelen + 1, MAXHOSTNAMELEN));
	return (0);
}

/*
 * Get the current PID; in standalone we always use 2 since it's the first
 * "mortal" PID.
 */
pid_t
getpid(void)
{
	return (2);
}

/*
 * Sleep for a given number of seconds
 */
unsigned int
sleep(unsigned int secs)
{
	uint_t end = (secs * 1000) + prom_gettime();

	while (prom_gettime() < end)
		/* Null body */;

	return (0);
}
