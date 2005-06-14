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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  rdate - get date from remote machine
 *
 *	sets time, obtaining value from host
 *	on the tcp/time socket.
 */

#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <stdio.h>

/*
 * The timeserver returns with time of day in seconds since
 * Jan 1, 1900. We must subtract 86400(365*70 + 17) to get time
 * since Jan 1, 1970, which is what get/settimeofday uses.
 */

#define	TOFFSET	((unsigned int)86400*(365*70 + 17))

/*
 * Before setting the system time, the value returned by the
 * timeserver is checked for plausibility. If the returned date
 * is before the time this program was written it cannot be
 * correct.
 */

#define	WRITTEN 440199955		/* 22:45:55 13/Dec/1983 */
#define	SECONDS_TO_MS	1000

static void timeout(int);

int
main(int argc, char **argv)
{
	int s, i;
	uint32_t time;
	struct timeval timestruct;
	unsigned int connect_timeout;
	/* number of seconds to wait for something to happen. */
	unsigned int rdate_timeout = 30;	/* seconds */
	struct addrinfo hints;
	struct addrinfo *res;
	int rc;

	if (argc != 2) {
		(void) fputs("usage: rdate host\n", stderr);
		exit(EXIT_FAILURE);
	}

	(void) memset(&hints, 0, sizeof (hints));
	hints.ai_protocol = IPPROTO_TCP;
	res = NULL;

	/*
	 * getaddrinfo() may take a long time, because it can involve
	 * NIS, DNS, or LDAP lookups. Set an alarm timer. Note that this
	 * may still fail, depending on how SIGALRM is handled by the
	 * functions invoked by getaddrinfo().
	 */

	(void) signal(SIGALRM, timeout);
	(void) alarm(rdate_timeout);

	/*
	 * Note: memory not freed due to short lifetime of program.
	 */

	rc = getaddrinfo(argv[1], "time", &hints, &res);
	(void) alarm(0);

	if (rc != 0) {
		(void) fprintf(stderr, "Host name %s not found: %s\n", argv[1],
		    gai_strerror(rc));
		exit(EXIT_FAILURE);
	}

	connect_timeout = rdate_timeout * SECONDS_TO_MS;
	for (; res != NULL; res = res->ai_next) {
		s = socket(res->ai_addr->sa_family, res->ai_socktype,
		    res->ai_protocol);
		if (s < 0) {
			perror("rdate: socket");
			exit(EXIT_FAILURE);
		}

		if (setsockopt(s, IPPROTO_TCP, TCP_CONN_ABORT_THRESHOLD,
		    (char *)&connect_timeout, sizeof (connect_timeout)) == -1) {
			perror("setsockopt TCP_CONN_ABORT_THRESHOLD");
		}

		if (connect(s, res->ai_addr, res->ai_addrlen) >= 0)
			break;

		if (res->ai_next == NULL) {
			perror("rdate: connect");
			(void) close(s);
			exit(EXIT_FAILURE);
		}

		(void) close(s);
	}

	(void) alarm(rdate_timeout);
	if (read(s, (char *)&time, sizeof (time)) != sizeof (time)) {
		perror("rdate: read");
		exit(EXIT_FAILURE);
	}
	(void) alarm(0);

	time = ntohl(time) - TOFFSET;
	/* date must be later than when program was written */
	if (time < WRITTEN) {
		(void) fprintf(stderr, "didn't get plausible time from %s\n",
		    argv[1]);
		exit(EXIT_FAILURE);
	}
	timestruct.tv_usec = 0;
	timestruct.tv_sec = time;
	i = settimeofday(&timestruct, 0);
	if (i == -1) {
		perror("couldn't set time of day");
		exit(EXIT_FAILURE);
	} else {
		(void) printf("%s", ctime(&timestruct.tv_sec));
#if defined(i386)
		(void) system("/usr/sbin/rtc -c > /dev/null 2>&1");
#endif
	}
	return (EXIT_SUCCESS);
}

/*ARGSUSED*/
static void
timeout(int sig)
{
	(void) fputs("couldn't contact time server\n", stderr);
	exit(EXIT_FAILURE);
	/* NOTREACHED */
}
