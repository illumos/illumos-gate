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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
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
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <libintl.h>

#ifdef SYSV
#define	bcopy(a, b, c)	(void) memcpy((b), (a), (c))
#endif

#define	MAX_SHORTSTRLEN 6

void _ruserpass(const char *host, char **aname, char **apass);

int rexec(char **ahost, unsigned short rport, const char *name,
    const char *pass, const char *cmd, int *fd2p)
{
		return (rexec_af(ahost, rport, name, pass, cmd, fd2p, AF_INET));
}

int rexec_af(char **ahost, unsigned short rport, const char *name,
    const char *pass, const char *cmd, int *fd2p, int af)
{
	int s, timo = 1, s3;
	char c;
	ushort_t port;
	static char hostname[MAXHOSTNAMELEN];
	int rc;
	struct addrinfo *res;
	struct addrinfo hints;
	char aport[MAX_SHORTSTRLEN];

	if (!(af == AF_INET || af == AF_INET6 || af == AF_UNSPEC)) {
		(void) fprintf(stderr,
		    dgettext(TEXT_DOMAIN, "%d: Address family not "
		    "supported\n"), af);
		errno = EAFNOSUPPORT;
		return (-1);
	}
	memset(&hints, 0, sizeof (hints));
	(void) snprintf(aport, MAX_SHORTSTRLEN, "%u", ntohs(rport));
	hints.ai_flags = AI_CANONNAME|AI_ADDRCONFIG|AI_V4MAPPED;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = af;
	rc = getaddrinfo(*ahost, aport, &hints, &res);

	if (rc != 0) {
		(void) fprintf(stderr,
		    dgettext(TEXT_DOMAIN, "%s: unknown host\n"),
		    *ahost);
		return (-1);
	}
	(void) strlcpy(hostname, res->ai_canonname, MAXHOSTNAMELEN);
	*ahost = hostname;
	_ruserpass(res->ai_canonname, (char **)&name, (char **)&pass);
retry:
	s = socket(res->ai_addr->sa_family, res->ai_socktype, res->ai_protocol);
	if (s < 0) {
		perror("rexec: socket");
		freeaddrinfo(res);
		return (-1);
	}
	if (connect(s, res->ai_addr, res->ai_addrlen) != 0) {
		if (errno == ECONNREFUSED && timo <= 16) {
			(void) close(s);
			(void) sleep(timo);
			timo *= 2;
			goto retry;
		}
		perror(*ahost);
		(void) close(s);
		freeaddrinfo(res);
		return (-1);
	}
	if (fd2p == 0) {
		(void) write(s, "", 1);
		port = 0;
	} else {
		int s2;
		socklen_t sin2len;
		struct sockaddr_storage sin2, from;

		s2 = socket(res->ai_family, SOCK_STREAM, 0);
		if (s2 < 0) {
			(void) close(s);
			freeaddrinfo(res);
			return (-1);
		}
		(void) listen(s2, 1);
		sin2len = (socklen_t)sizeof (sin2);
		if (getsockname(s2, (struct sockaddr *)&sin2, &sin2len) < 0) {
			perror("getsockname");
			(void) close(s2);
			goto bad;
		}
		if (res->ai_family == AF_INET6) {
			port = ntohs(((struct sockaddr_in6 *)&sin2)->sin6_port);
		} else {
			port = ntohs(((struct sockaddr_in *)&sin2)->sin_port);
		}
		(void) snprintf(aport, MAX_SHORTSTRLEN, "%u", port);
		(void) write(s, aport, strlen(aport)+1);
		{
			socklen_t len = (socklen_t)sizeof (from);
			s3 = accept(s2, (struct sockaddr *)&from, &len);
			(void) close(s2);
			if (s3 < 0) {
				perror("accept");
				port = 0;
				goto bad;
			}
		}
		*fd2p = s3;
	}
	(void) write(s, name, strlen(name) + 1);
	/* should public key encypt the password here */
	(void) write(s, pass, strlen(pass) + 1);
	(void) write(s, cmd, strlen(cmd) + 1);
	if (read(s, &c, 1) != 1) {
		perror(*ahost);
		goto bad;
	}
	if (c != 0) {
		while (read(s, &c, 1) == 1) {
			(void) write(2, &c, 1);
			if (c == '\n')
				break;
		}
		goto bad;
	}
	freeaddrinfo(res);
	return (s);
bad:
	if (port)
		(void) close(*fd2p);
	(void) close(s);
	freeaddrinfo(res);
	return (-1);
}
