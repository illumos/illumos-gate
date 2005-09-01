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
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <stdio.h>
#include <netdb.h>

#define	OUTFILE		"hosts.txt"	/* default output file */
#define	VERFILE		"hosts.ver"	/* default version file */
#define	QUERY		"ALL\r\n"	/* query to hostname server */
#define	VERSION		"VERSION\r\n"	/* get version number */

#define	equaln(s1, s2, n)	(!strncmp(s1, s2, n))

#ifdef SYSV
#define bcopy(a,b,c)	  memcpy(b,a,c)
#endif

struct	sockaddr_in sin;
struct	sockaddr_in sintmp;
char	buf[BUFSIZ];
char	*outfile = OUTFILE;

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int s;
	register int len;
	register FILE *sfi, *sfo, *hf;
	char *host;
	register struct hostent *hp;
	struct servent *sp;
	int version = 0;
	int beginseen = 0;
	int endseen = 0;

	argv++, argc--;
	if (argc > 0 && **argv == '-') {
		if (argv[0][1] != 'v')
			fprintf(stderr, "unknown option %s ignored\n", *argv);
		else
			version++, outfile = VERFILE;
		argv++, argc--;
	}
	if (argc < 1 || argc > 2) {
		fprintf(stderr, "usage: gettable [-v] host [ file ]\n");
		exit(1);
	}
	sp = getservbyname("hostnames", "tcp");
	if (sp == NULL) {
		fprintf(stderr, "gettable: hostnames/tcp: unknown service\n");
		exit(3);
	}
	host = *argv;
	argv++, argc--;
	sintmp.sin_addr.s_addr = inet_addr(host);
	if (sintmp.sin_addr.s_addr != -1 && sintmp.sin_addr.s_addr != 0) {
		sin.sin_family = AF_INET;
	} else {
		hp = gethostbyname(host);
		if (hp == NULL) {
			fprintf(stderr, "gettable: %s: host unknown\n", host);
			exit(2);
		} else {
			sin.sin_family = hp->h_addrtype;
			host = hp->h_name;
		}
	}
	if (argc > 0)
		outfile = *argv;
	s = socket(sin.sin_family, SOCK_STREAM, 0);
	if (s < 0) {
		perror("gettable: socket");
		exit(4);
	}
	if (bind(s, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
		perror("gettable: bind");
		exit(5);
	}
	if (sintmp.sin_addr.s_addr != -1 && sintmp.sin_addr.s_addr != 0)
		bcopy((char *)&sintmp.sin_addr, (char *)&sin.sin_addr,
			sizeof(sintmp.sin_addr));
	else
		bcopy(hp->h_addr, (char *)&sin.sin_addr, hp->h_length);
	sin.sin_port = sp->s_port;
	if (connect(s, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
		perror("gettable: connect");
		exit(6);
	}
	fprintf(stderr, "Connection to %s opened.\n", host);
	sfi = fdopen(s, "r");
	sfo = fdopen(s, "w");
	if (sfi == NULL || sfo == NULL) {
		perror("gettable: fdopen");
		close(s);
		exit(1);
	}
	hf = fopen(outfile, "w");
	if (hf == NULL) {
		fprintf(stderr, "gettable: "); perror(outfile);
		close(s);
		exit(1);
	}
	fprintf(sfo, version ? VERSION : QUERY);
	fflush(sfo);
	while (fgets(buf, sizeof(buf), sfi) != NULL) {
		len = strlen(buf);
		buf[len-2] = '\0';
		if (!version && equaln(buf, "BEGIN", 5)) {
			if (beginseen || endseen) {
				fprintf(stderr,
				    "gettable: BEGIN sequence error\n");
				exit(90);
			}
			beginseen++;
			continue;
		}
		if (!version && equaln(buf, "END", 3)) {
			if (!beginseen || endseen) {
				fprintf(stderr,
				    "gettable: END sequence error\n");
				exit(91);
			}
			endseen++;
			continue;
		}
		if (equaln(buf, "ERR", 3)) {
			fprintf(stderr,
			    "gettable: hostname service error: %s", buf);
			exit(92);
		}
		fprintf(hf, "%s\n", buf);
	}
	fclose(hf);
	if (!version) {
		if (!beginseen) {
			fprintf(stderr, "gettable: no BEGIN seen\n");
			exit(93);
		}
		if (!endseen) {
			fprintf(stderr, "gettable: no END seen\n");
			exit(94);
		}
		fprintf(stderr, "Host table received.\n");
	} else
		fprintf(stderr, "Version number received.\n");
	close(s);
	fprintf(stderr, "Connection to %s closed\n", host);
	return (0);
}
