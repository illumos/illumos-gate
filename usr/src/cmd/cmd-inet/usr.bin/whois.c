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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define	NICHOST	"whois.internic.net"

int
main(int argc, char *argv[])
{
	int s, rv;
	register FILE *sfi, *sfo;
	register int c;
	char *host = NICHOST;
	struct addrinfo *ai_head, *ai;
	struct addrinfo hints;

	argc--, argv++;
	if (argc > 2 && strcmp(*argv, "-h") == 0) {
		argv++, argc--;
		host = *argv++;
		argc--;
	}
	if (argc != 1) {
		(void) fprintf(stderr, "usage: whois [ -h host ] name\n");
		exit(1);
	}

	memset(&hints, 0, sizeof (hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_ADDRCONFIG;
	rv = getaddrinfo(host, "whois", &hints, &ai_head);
	if (rv != 0) {
		(void) fprintf(stderr, "whois: %s: %s\n", host,
		    gai_strerror(rv));
		exit(1);
	}

	for (ai = ai_head; ai != NULL; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s >= 0) {
			rv = connect(s, ai->ai_addr, ai->ai_addrlen);
			if (rv < 0)
				(void) close(s);
			else
				break;
		}
	}
	if (ai_head != NULL)
		freeaddrinfo(ai_head);

	if (s < 0) {
		perror("whois: socket");
		exit(2);
	} else if (rv < 0) {
		perror("whois: connect");
		exit(5);
	}

	sfi = fdopen(s, "r");
	sfo = fdopen(s, "w");
	if (sfi == NULL || sfo == NULL) {
		perror("fdopen");
		(void) close(s);
		exit(1);
	}
	(void) fprintf(sfo, "%s\r\n", *argv);
	(void) fflush(sfo);
	while ((c = getc(sfi)) != EOF)
		(void) putchar(c);
	return (0);
}
