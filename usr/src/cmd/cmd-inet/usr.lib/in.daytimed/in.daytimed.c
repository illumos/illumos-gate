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
 * daytime inetd service - both stream and dgram based.
 * Return human-readable time of day.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <strings.h>
#include <netinet/in.h>
#include <inetsvc.h>


#define	TIMEBUF_SIZE	26


static const char *
daytime(void)
{
	time_t		clock;
	static char	buf[TIMEBUF_SIZE];

	clock = time(NULL);
	(void) strlcpy(buf, ctime(&clock), sizeof (buf));
	/*
	 * Format of ctime is "Fri Sep 13 00:00:00 1986\n\0". To conform to the
	 * required format as specified in RFCs 867 and 854 we replace the
	 * "\n\0" with "\r\n".
	 */
	buf[TIMEBUF_SIZE - 2] = '\r';
	buf[TIMEBUF_SIZE - 1] = '\n';

	return (buf);
}

/* ARGSUSED3 */
static void
daytime_dg(int s, const struct sockaddr *sap, int sa_size, const void *buf,
    size_t sz)
{
	(void) safe_sendto(s, daytime(), TIMEBUF_SIZE, 0, sap, sa_size);
}

int
main(int argc, char *argv[])
{
	opterr = 0;	/* disable getopt error msgs */
	switch (getopt(argc, argv, "ds")) {
	case 'd':
		dg_template(daytime_dg, STDIN_FILENO, NULL, 0);
		break;
	case 's':
		(void) safe_write(STDIN_FILENO, daytime(), TIMEBUF_SIZE);
		break;
	default:
		return (1);
	}

	return (0);
}
