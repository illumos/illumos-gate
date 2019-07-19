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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * mconnect.c - A program to test out SMTP connections.
 * Usage: mconnect [host]
 *  ... SMTP dialog
 *  ^C or ^D or QUIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <sgtty.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <errno.h>

union bigsockaddr
{
	struct sockaddr		sa;	/* general version */
	struct sockaddr_in	sin;	/* INET family */
	struct sockaddr_in6	sin6;	/* INET/IPv6 */
};

static struct sgttyb TtyBuf;
static int raw = 0;

/* ARGSUSED */
static void
finis(sig)
	int sig;
{
	if (raw)
		(void) ioctl(0, TIOCSETP, &TtyBuf);
	exit(0);
}

int
main(argc, argv)
	int argc;
	char **argv;
{
	union bigsockaddr SendmailAddress;
	register int s;
	char *host = NULL;
	int pid;
	int on = 1;
	struct servent *sp;
	char buf[1000];
	register FILE *f;
	register struct hostent *hp;
	in_port_t port = 0;
	int err;
	char buf6[INET6_ADDRSTRLEN];
	int addr_num = 0;
	int addrlen;

	(void) ioctl(0, TIOCGETP, &TtyBuf);
	(void) signal(SIGINT, finis);

	while (--argc > 0)
	{
		register char *p;

		p = *++argv;
		if (*p == '-')
		{
			switch (*++p)
			{
			    case 'h':		/* host */
				break;

			    case 'p':		/* port */
				port = htons(atoi(*++argv));
				argc--;
				break;

			    case 'r':		/* raw connection */
				raw = 1;
				break;
			}
		} else if (host == NULL)
			host = p;
	}
	if (host == NULL)
		host = "localhost";

	bzero(&SendmailAddress, sizeof (SendmailAddress));
	hp = getipnodebyname(host, AF_INET6, AI_DEFAULT|AI_ALL, &err);
	if (hp == NULL)
	{
		(void) fprintf(stderr, "mconnect: unknown host %s\r\n", host);
		exit(0);
	}

	if (port == 0) {
		sp = getservbyname("smtp", "tcp");
		if (sp != NULL)
			port = sp->s_port;
	}

	for (;;) {
		bcopy(hp->h_addr_list[addr_num],
		    &SendmailAddress.sin6.sin6_addr, IN6ADDRSZ);
		if (IN6_IS_ADDR_V4MAPPED(&SendmailAddress.sin6.sin6_addr)) {
			SendmailAddress.sa.sa_family = AF_INET;
			SendmailAddress.sin.sin_port = port;
			bcopy(&hp->h_addr_list[addr_num][IN6ADDRSZ - INADDRSZ],
				&SendmailAddress.sin.sin_addr, INADDRSZ);
			addrlen = sizeof (struct sockaddr_in);
		} else {
			SendmailAddress.sa.sa_family = AF_INET6;
			SendmailAddress.sin6.sin6_port = port;
			addrlen = sizeof (struct sockaddr_in6);
		}

		s = socket(SendmailAddress.sa.sa_family, SOCK_STREAM, 0);
		if (s < 0)
		{
			perror("socket");
			exit(-1);
		}
		(void) setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *)&on,
		    sizeof (on));
		if (SendmailAddress.sa.sa_family == AF_INET)
			(void) printf("connecting to host %s (%s), port %d\r\n",
				host, inet_ntoa(SendmailAddress.sin.sin_addr),
				ntohs(SendmailAddress.sin.sin_port));
		else
			(void) printf("connecting to host %s (%s), port %d\r\n",
				host, inet_ntop(AF_INET6,
					SendmailAddress.sin6.sin6_addr.s6_addr,
					buf6, sizeof (buf6)),
				ntohs(SendmailAddress.sin6.sin6_port));
		if (connect(s, (struct sockaddr *)&SendmailAddress,
				addrlen) >= 0)
			break;
		if (hp->h_addr_list[++addr_num] != NULL) {
			(void) printf("connect failed (%s), next address ...\n",
				strerror(errno));
			bcopy(hp->h_addr_list[addr_num],
				&SendmailAddress.sin6.sin6_addr, IN6ADDRSZ);
			if (IN6_IS_ADDR_V4MAPPED(
			    &SendmailAddress.sin6.sin6_addr)) {
				SendmailAddress.sa.sa_family = AF_INET;
				bcopy(&hp->h_addr_list[addr_num]
				    [IN6ADDRSZ - INADDRSZ],
					&SendmailAddress.sin.sin_addr,
					INADDRSZ);
				addrlen = sizeof (struct sockaddr_in);
			} else {
				SendmailAddress.sa.sa_family = AF_INET6;
				addrlen = sizeof (struct sockaddr_in6);
			}
			continue;
		}
		perror("connect");
		exit(-1);
	}

	if (raw) {
		TtyBuf.sg_flags &= ~CRMOD;
		(void) ioctl(0, TIOCSETP, &TtyBuf);
		TtyBuf.sg_flags |= CRMOD;
	}

	/* good connection, fork both sides */
	(void) printf("connection open\n");
	pid = fork();
	if (pid < 0)
	{
		perror("fork");
		exit(-1);
	}
	if (pid == 0)
	{
		/* child -- standard input to sendmail */
		int c;

		f = fdopen(s, "w");
		while ((c = fgetc(stdin)) >= 0)
		{
			if (!raw && c == '\n')
				(void) fputc('\r', f);
			(void) fputc(c, f);
			if (c == '\n')
				(void) fflush(f);
		}
		(void) shutdown(s, 1);
		(void) sleep(10);
	}
	else
	{
		/* parent -- sendmail to standard output */
		f = fdopen(s, "r");
		while (fgets(buf, sizeof (buf), f) != NULL)
		{
			(void) fputs(buf, stdout);
			(void) fflush(stdout);
		}
		(void) kill(pid, SIGTERM);
	}
	if (raw)
		(void) ioctl(0, TIOCSETP, &TtyBuf);
	return (0);
}
