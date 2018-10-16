/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 */

/*
 * Test helper to abort TCP connections to some server;
 * either all of the, or those to a specified port.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/stropts.h>

#include <inet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zone.h>

/*
 * Abort all connections to the passed address.
 */
static void
tcp_abort_connections(struct sockaddr *rsa)
{
	tcp_ioc_abort_conn_t conn;
	struct strioctl ioc;
	struct sockaddr *lsa;
	int fd;

	(void) memset(&conn, 0, sizeof (conn));
	lsa = (void *)&conn.ac_local;
	lsa->sa_family = rsa->sa_family;
	(void) memcpy(&conn.ac_remote, rsa, sizeof (*rsa));
	conn.ac_start = TCPS_SYN_SENT;
	conn.ac_end = TCPS_CLOSE_WAIT;
	conn.ac_zoneid = ALL_ZONES;

	ioc.ic_cmd = TCP_IOC_ABORT_CONN;
	ioc.ic_timout = -1; /* infinite timeout */
	ioc.ic_len = sizeof (conn);
	ioc.ic_dp = (char *)&conn;

	if ((fd = open("/dev/tcp", O_RDONLY)) < 0) {
		(void) fprintf(stderr, "unable to open %s", "/dev/tcp");
		return;
	}

	if (ioctl(fd, I_STR, &ioc) < 0)
		if (errno != ENOENT)	/* ENOENT is not an error */
			perror("ioctl");

	(void) close(fd);
}

static void
usage(char *arg0)
{
	(void) fprintf(stderr, "usage: %s [-p <PORT>] <ADDR>\n", arg0);
	exit(1);
}

int
main(int argc, char **argv)
{
	extern char *optarg;
	extern int optind, optopt;
	struct addrinfo hints, *res, *ai;
	char *addr_str = NULL;
	char *port_str = NULL;
	int errflag = 0;
	int c, gaierr;

	while ((c = getopt(argc, argv, "p:")) != -1) {
		switch (c) {
		case 'p':
			port_str = optarg;
			break;
		case ':':
			(void) fprintf(stderr,
			    "Option -%c requires an operand\n", optopt);
			errflag++;
			break;
		case '?':
			(void) fprintf(stderr,
			    "Unrecognized option: -%c\n", optopt);
			errflag++;
			break;
		}
	}
	if (errflag)
		usage(argv[0]);
	if (argc <= optind) {
		(void) fprintf(stderr, "No address specified\n");
		usage(argv[0]);
	}
	addr_str = argv[optind];

	/*
	 * Lookup the IP address
	 */
	(void) memset(&hints, 0, sizeof (hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	gaierr = getaddrinfo(addr_str, port_str, &hints, &res);
	if (gaierr != 0) {
		(void) fprintf(stderr, "%s: %s\n", addr_str,
		    gai_strerror(gaierr));
		return (1);
	}

	for (ai = res; ai != NULL; ai = ai->ai_next) {
		tcp_abort_connections(ai->ai_addr);
	}

	return (0);
}
