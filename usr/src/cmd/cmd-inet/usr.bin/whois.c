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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <stdio.h>
#include <netdb.h>

#ifdef SYSV
#define	bcopy(a,b,c)	memcpy((b),(a),(c))
#endif /* SYSV */

#define	NICHOST	"whois.internic.net"

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int s;
	register FILE *sfi, *sfo;
	register int c;
	char *host = NICHOST;
	struct sockaddr_in sin;
	struct hostent *hp;
	struct servent *sp;
	char hnamebuf[32];
	int addrtype;

	argc--, argv++;
	if (argc > 2 && strcmp(*argv, "-h") == 0) {
		argv++, argc--;
		host = *argv++;
		argc--;
	}
	if (argc != 1) {
		fprintf(stderr, "usage: whois [ -h host ] name\n");
		exit(1);
	}
	sin.sin_addr.s_addr = inet_addr(host);
	if (sin.sin_addr.s_addr != -1 && sin.sin_addr.s_addr != 0) {
		addrtype = AF_INET;
	} else {
		hp = gethostbyname(host);
		if (hp == NULL) {
			fprintf(stderr, "whois: %s: host unknown\n", host);
			exit(1);
		}
		addrtype = hp->h_addrtype;
		host = hp->h_name;
		bcopy(hp->h_addr, &sin.sin_addr, hp->h_length);
	}

	s = socket(addrtype, SOCK_STREAM, 0);
	if (s < 0) {
		perror("whois: socket");
		exit(2);
	}
	sin.sin_family = addrtype;
	sp = getservbyname("whois", "tcp");
	if (sp == NULL) {
		sin.sin_port = htons(IPPORT_WHOIS);
	}
	else sin.sin_port = sp->s_port;
	if (connect(s, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
		perror("whois: connect");
		exit(5);
	}
	sfi = fdopen(s, "r");
	sfo = fdopen(s, "w");
	if (sfi == NULL || sfo == NULL) {
		perror("fdopen");
		close(s);
		exit(1);
	}
	fprintf(sfo, "%s\r\n", *argv);
	fflush(sfo);
	while ((c = getc(sfi)) != EOF)
		putchar(c);
	return (0);
}
