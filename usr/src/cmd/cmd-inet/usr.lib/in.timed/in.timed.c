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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * time inetd service - both stream and dgram based.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <syslog.h>
#include <inetsvc.h>


/*
 * Return a machine readable date and time, in the form of the
 * number of seconds since midnight, Jan 1, 1900.  Since gettimeofday
 * returns the number of seconds since midnight, Jan 1, 1970,
 * we must add 2208988800 seconds to this figure to make up for
 * some seventy years Bell Labs was asleep.
 */
static uint32_t
machtime(void)
{
	struct timeval tv;

	if (gettimeofday(&tv, NULL) < 0) {
		syslog(LOG_INFO, "Unable to get time of day");
		return (0);
	}
	return ((uint32_t)htonl(tv.tv_sec + 2208988800U));
}

static void
machtime_stream(int s)
{
	uint32_t result = machtime();

	(void) safe_write(s, &result, sizeof (result));
}

/* ARGSUSED3 */
static void
machtime_dg(int s, const struct sockaddr *sap, int sa_len, const void *buf,
    size_t sz)
{
	uint32_t result = machtime();

	(void) safe_sendto(s, &result, sizeof (result), 0, sap, sa_len);
}

int
main(int argc, char *argv[])
{
	opterr = 0;	/* disable getopt error msgs */
	switch (getopt(argc, argv, "ds")) {
	case 'd':
		dg_template(machtime_dg, STDIN_FILENO, NULL, 0);
		break;
	case 's':
		machtime_stream(STDIN_FILENO);
		break;
	default:
		return (1);
	}

	return (0);
}
