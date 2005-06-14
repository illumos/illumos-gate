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
 *
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 * All Rights Reserved.
 */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California.
 * All Rights Reserved.
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This program implements a UDP basic name server as specified in IEN116
 * The extended name server functionality is NOT implemented here (yet).
 * This is generally used in conjunction with MIT's PC/IP software.
 */

#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#ifdef SYSV
#define	bzero(s, n)	memset((s), 0, (n))
#define	bcopy(a, b, c)	memcpy((b), (a), (c))
#endif /* SYSV */

/*
 * These command codes come from IEN116
 */
#define	NAMECODE	1
#define	ADDRESSCODE	2
#define	ERRORCODE	3
/*
 * These error codes are used to qualify ERRORCODE
 */
#define	UNDEFINEDERROR	0
#define	NOTFOUNDERROR	1
#define	SYNTAXERROR	2
#define	BUFLEN 2000
static int handler();

main(argc, argv)
	int argc;
	char **argv;
{
	int s;
	struct sockaddr_in client;
	int length;
	socklen_t clientlength;
	register struct hostent	*hp;
	char hostname[BUFLEN];
	char iobuf[BUFLEN];
	register char *buffer = iobuf;
	register int replylength;
	int request;
	struct in_addr x;

	if (argc > 1) {
		/* the daemon is run by hand and never exits */
		struct servent temp;
		register struct servent *sp;
		register struct protoent *pp;
		struct sockaddr_in server;

		if ((sp = getservbyname("name", "udp")) == NULL) {
			fprintf(stderr, "in.tnamed: UDP name server not in ");
			fprintf(stderr, "/etc/services\n");
			sp = &temp;
			sp->s_port = htons(42);
		}
		if ((pp = getprotobyname("udp")) == NULL) {
			fprintf(stderr, "in.tnamed: UDP protocol not in ");
			fprintf(stderr, "/etc/protocols\n");
			exit(1);
		}
		if ((s = socket(AF_INET, SOCK_DGRAM, pp->p_proto)) < 0) {
			perror("in.tnamed: socket error");
			exit(1);
		}
		bzero((char *)&server, sizeof (server));
		server.sin_family = AF_INET;
		server.sin_port = sp->s_port;
		if (bind(s, (struct sockaddr *)&server, sizeof (server)) != 0) {
			perror("in.tnamed: bind error");
			exit(1);
		}
		fprintf(stderr, "in.tnamed: UDP name server running\n");
	} else {
		/* daemon forked by inetd and is short lived */
		struct itimerval value, ovalue;

		signal(SIGALRM, (void (*)())handler);
		value.it_value.tv_sec = 5 * 60;
		value.it_value.tv_usec = value.it_interval.tv_usec = 0;
		setitimer(ITIMER_REAL, &value, &ovalue);
		s = 0;  /* by inetd conventions */
	}

	for (;;) {

		clientlength = (socklen_t)sizeof (client);
		length = recvfrom(s, buffer, BUFLEN, 0,
		    (struct sockaddr *)&client, &clientlength);
		if (length < 0) {
			perror("in.tnamed: recvfrom error.Try in.tnamed -v ?");
			continue;
		}

		request = buffer[0];
		length = buffer[1];
		replylength = length + 2;  /* reply is appended to request */
		if (length < sizeof (hostname)) {
			strncpy(hostname, &buffer[2], length);
			hostname[length] = 0;
		} else {
			hostname[0] = 0;
		}

		if (request != NAMECODE) {
			fprintf(stderr, "in.tnamed: bad request from %s\n",
			    inet_ntoa(client.sin_addr));
			buffer[replylength++] = ERRORCODE;
			buffer[replylength++] = 3;  /* no error msg yet */
			buffer[replylength++] = SYNTAXERROR;
			fprintf(stderr,
			    "in.tnamed: request (%d) not NAMECODE\n", request);
			sleep(5);  /* pause before saying something negative */
			goto sendreply;
		}

		if (hostname[0] == '!') {
			/*
			 * !host!net name format is not implemented yet,
			 * only host alone.
			 */
			fprintf(stderr, "in.tnamed: %s ",
			    inet_ntoa(client.sin_addr));
			fprintf(stderr, "using !net!host format name ");
			fprintf(stderr, "request\n");

			buffer[replylength++] = ERRORCODE;
			buffer[replylength++] = 0;  /* no error msg yet */
			buffer[replylength++] = UNDEFINEDERROR;
			fprintf(stderr,
			    "in.tnamed: format (%s) not supported\n", hostname);
			sleep(5);  /* pause before saying something negative */
			goto sendreply;
		}

		if ((hp = gethostbyname(hostname)) == NULL) {
			buffer[replylength++] = ERRORCODE;
			buffer[replylength++] = 0;  /* no error msg yet */
			buffer[replylength++] = NOTFOUNDERROR;
			fprintf(stderr, "in.tnamed: name (%s) not found\n",
			    hostname);
			sleep(5);  /* pause before saying something negative */
			goto sendreply;
		}

		if (hp->h_addrtype != AF_INET) {
			buffer[replylength++] = ERRORCODE;
			buffer[replylength++] = 0;  /* no error msg yet */
			buffer[replylength++] = UNDEFINEDERROR;
			fprintf(stderr,
			    "in.tnamed: address type (%d) not AF_INET\n",
			    hp->h_addrtype);
			sleep(5);  /* pause before saying something negative */
			goto sendreply;
		}

		fprintf(stderr, "in.tnamed: %s asked for address of %s",
		    inet_ntoa(client.sin_addr), hostname);
		bcopy(hp->h_addr, (char *)&x, sizeof (x));
		printf(" - it's %s\n", inet_ntoa(x));

		buffer[replylength++] = ADDRESSCODE;
		buffer[replylength++] = hp->h_length;
		bcopy(hp->h_addr, &buffer[replylength], hp->h_length);
		replylength += hp->h_length;

	sendreply:
		if (sendto(s, buffer, replylength, 0,
		    (struct sockaddr *)&client, clientlength)
		    != replylength) {
			perror("in.tnamed: sendto error");
			continue;
		}
	}
}

static int
handler()
{

	exit(0);
}
