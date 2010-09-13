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
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <myrcmd.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/file.h>
#include <signal.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>
#include <fcntl.h>
#include <libintl.h>

#include <memutils.h>

#define	index(s, c)		strchr(s, c)
char	*strchr();

char	*inet_ntoa();

char myrcmd_stderr[1024];

int
myrcmd(char **ahost, unsigned short rport, char *locuser, char *remuser,
    char *cmd)
{
	uint_t loclen, remlen, cmdlen;
	int s, timo, retval;
	int tries = 0;
	pid_t pid;
	struct sockaddr_in sin;
	char c;
	int lport;
	int saverr;
	struct hostent *hp;
	sigset_t oldmask;
	sigset_t newmask;
	struct sigaction oldaction;
	struct sigaction newaction;
	static struct hostent numhp;
	static char numhostname[32];	/* big enough for "255.255.255.255" */
	struct in_addr numaddr;
	struct in_addr *numaddrlist[2];

	myrcmd_stderr[0] = '\0';	/* empty error string */
	pid = getpid();
	hp = gethostbyname(*ahost);
	if (hp == 0) {
		char *straddr;

		bzero((char *)numaddrlist, sizeof (numaddrlist));
		if ((numaddr.s_addr = inet_addr(*ahost)) == (in_addr_t)-1) {
			(void) snprintf(myrcmd_stderr, sizeof (myrcmd_stderr),
			    gettext("%s: unknown host\n"), *ahost);
			return (MYRCMD_NOHOST);
		} else {
			bzero((char *)&numhp, sizeof (numhp));
			bzero(numhostname, sizeof (numhostname));

			if ((straddr = inet_ntoa(numaddr)) == (char *)0) {
				(void) snprintf(myrcmd_stderr,
				    sizeof (myrcmd_stderr),
				    gettext("%s: unknown host\n"), *ahost);
				return (MYRCMD_NOHOST);
			}
			(void) strncpy(numhostname, straddr,
			    sizeof (numhostname));
			numhostname[sizeof (numhostname) - 1] = '\0';
			numhp.h_name = numhostname;
			numhp.h_addrtype = AF_INET;
			numhp.h_length = sizeof (numaddr);
			numaddrlist[0] = &numaddr;
			numaddrlist[1] = NULL;
			numhp.h_addr_list = (char **)numaddrlist;
			hp = &numhp;
		}
	}
	*ahost = hp->h_name;

	/* This provides a bounds-test for the bcopy()s below. */
	if ((unsigned)(hp->h_length) > sizeof (sin.sin_addr)) {
		(void) snprintf(myrcmd_stderr, sizeof (myrcmd_stderr),
		    gettext("rcmd: address size: %d larger than limit %d\n"),
		    hp->h_length, sizeof (sin.sin_addr));
		return (MYRCMD_EBAD);
	}

	/* ignore SIGPIPE */
	bzero((char *)&newaction, sizeof (newaction));
	newaction.sa_handler = SIG_IGN;
	newaction.sa_flags = SA_ONSTACK;
	(void) sigaction(SIGPIPE, &newaction, &oldaction);

	/* block SIGURG */
	bzero((char *)&newmask, sizeof (newmask));
	(void) sigaddset(&newmask, SIGURG);
	(void) sigprocmask(SIG_BLOCK, &newmask, &oldmask);
again:
	timo = 1;
	/*
	 * Use 0 as lport means that rresvport() will bind to a port in
	 * the anonymous priviledged port range.
	 */
	lport = 0;
	for (;;) {
		s = rresvport(&lport);
		if (s < 0) {
			int err;

			if (errno == EAGAIN) {
				(void) snprintf(myrcmd_stderr,
				    sizeof (myrcmd_stderr),
				    gettext("socket: All ports in use\n"));
				err = MYRCMD_ENOPORT;
			} else {
				saverr = errno;
				(void) snprintf(myrcmd_stderr,
				    sizeof (myrcmd_stderr),
				    gettext("rcmd: socket: %s\n"),
				    strerror(saverr));
				err = MYRCMD_ENOSOCK;
			}
			/* restore original SIGPIPE handler */
			(void) sigaction(SIGPIPE, &oldaction,
			    (struct sigaction *)0);

			/* restore original signal mask */
			(void) sigprocmask(SIG_SETMASK, &oldmask,
			    (sigset_t *)0);
			return (err);
		}
		/* Can't fail, according to fcntl(2) */
		(void) fcntl(s, F_SETOWN, pid);
		sin.sin_family = hp->h_addrtype;
		bcopy(hp->h_addr_list[0], (caddr_t)&sin.sin_addr, hp->h_length);
		sin.sin_port = rport;
		if (connect(s, (struct sockaddr *)&sin, sizeof (sin)) >= 0)
			break;
		saverr = errno;
		(void) close(s);
		if (saverr == EADDRINUSE) {
			continue;
		}
		if (saverr == ECONNREFUSED && timo <= 16) {
			sleep(timo);
			timo *= 2;
			continue;
		}
		if (hp->h_addr_list[1] != NULL) {
			saverr = errno;

			fprintf(stderr,
			    gettext("connect to address %s: "),
			    inet_ntoa(sin.sin_addr));
			errno = saverr;
			perror(0);
			hp->h_addr_list++;
			bcopy(hp->h_addr_list[0], (caddr_t)&sin.sin_addr,
			    hp->h_length);
			fprintf(stderr, gettext("Trying %s...\n"),
				inet_ntoa(sin.sin_addr));
			continue;
		}
		(void) snprintf(myrcmd_stderr, sizeof (myrcmd_stderr),
		    "%s: %s\n", hp->h_name, strerror(saverr));
		/* restore original SIGPIPE handler */
		(void) sigaction(SIGPIPE, &oldaction,
		    (struct sigaction *)0);

		/* restore original signal mask */
		(void) sigprocmask(SIG_SETMASK, &oldmask, (sigset_t *)0);
		return (MYRCMD_ENOCONNECT);
	}
	if (write(s, "", 1) < 0) {
		(void) close(s);
		return (MYRCMD_ENOCONNECT);
	}

	loclen = strlen(locuser) + 1;
	remlen = strlen(remuser) + 1;
	cmdlen = strlen(cmd) + 1;

	if (((retval = write(s, locuser, loclen)) != loclen) ||
	    ((retval = write(s, remuser, remlen)) != remlen) ||
	    ((retval = write(s, cmd, cmdlen)) != cmdlen)) {
		if (retval == -1)
			(void) snprintf(myrcmd_stderr, sizeof (myrcmd_stderr),
			    "write: %s\n", strerror(errno));
		else
			(void) snprintf(myrcmd_stderr, sizeof (myrcmd_stderr),
			    gettext("write unexpectedly truncated\n"));
		goto bad;
	}
	retval = read(s, &c, 1);
	if (retval != 1) {
		if (retval == 0) {
			/*
			 * Solaris 2.0 bug alert.  Sometimes, if the
			 * tapehost is a Solaris 2.0 system, the connection
			 * will be dropped at this point.  Let's try again,
			 * three times, before we throw in the towel.
			 */
			if (++tries < 3) {
				(void) close(s);
				goto again;
			}
			(void) snprintf(myrcmd_stderr, sizeof (myrcmd_stderr),
			    gettext("Protocol error, %s closed connection\n"),
			    *ahost);
		} else if (retval < 0) {
			(void) snprintf(myrcmd_stderr, sizeof (myrcmd_stderr),
			    "%s: %s\n", *ahost, strerror(errno));
		} else {
			(void) snprintf(myrcmd_stderr, sizeof (myrcmd_stderr),
			    gettext("Protocol error, %s sent %d bytes\n"),
			    *ahost, retval);
		}
		goto bad;
	}
	if (c != 0) {
		char *cp = myrcmd_stderr;
		char *ecp = &myrcmd_stderr[sizeof (myrcmd_stderr) - 1];

		while (read(s, &c, 1) == 1) {
			*cp++ = c;
			if (c == '\n' || cp >= ecp)
				break;
		}
		*cp = '\0';
		goto bad;
	}
	/* restore original SIGPIPE handler */
	(void) sigaction(SIGPIPE, &oldaction, (struct sigaction *)0);

	/* restore original signal mask */
	(void) sigprocmask(SIG_SETMASK, &oldmask, (sigset_t *)0);
	return (s);
bad:
	(void) close(s);
	/* restore original SIGPIPE handler */
	(void) sigaction(SIGPIPE, &oldaction, (struct sigaction *)0);

	/* restore original signal mask */
	(void) sigprocmask(SIG_SETMASK, &oldmask, (sigset_t *)0);
	return (MYRCMD_EBAD);
}
