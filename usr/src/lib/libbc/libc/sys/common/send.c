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
 * Copyright (c) 1990-1997 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syslog.h>
#include <sys/strlog.h>
#include <sys/stropts.h>
#include <stdio.h>

extern int errno;

#define	N_AGAIN	11

int
send(s, msg, len, flags)
	int	s;
	char	*msg;
	int	len, flags;
{
	int	a;
	if ((a = _send(s, msg, len, flags)) == -1) {
		if (errno == N_AGAIN)
			errno = EWOULDBLOCK;
		else
			maperror();
	}
	return (a);
}


/* Added to convert socket "/dev/log" to stream "/dev/conslog" */
#define	logname		"/dev/conslog"
#define	MAXLINE		1024
#define	SVR4_ENOTSOCK	95	/* Socket operation on non-socket */


int
sendto(s, msg, len, flags, to, tolen)
	int	s;
	char	*msg;
	int	len, flags;
	struct sockaddr *to;
	int	tolen;
{
	int	a;
	static int LogDev = -1;
	/* check for  logfile */

	if ((a = _sendto(s, msg, len, flags, to, tolen)) == -1) {
		if (errno == SVR4_ENOTSOCK &&
		    strcmp(to->sa_data, "/dev/log") == 0) {
			char *msg_p;
			struct log_ctl hdr;
			struct strbuf dat;
			struct strbuf ctl;
			struct stat sbuf;
			if (LogDev == -1) {
				int	tfd;
				/* close socket /dev/log */
				close(s);
				/* open stream /dev/conslog */
				tfd = open(logname, O_WRONLY);
				if (tfd == -1)
					return (-1);
				/* insure stream has same fd as closed socket */
				if (tfd != s) {
					if (dup2(tfd, s) < 0) {
						close(tfd);
						return (-1);
					}
					close(tfd);
				}
				if (fcntl(s, F_SETFD, FD_CLOEXEC) == -1)
					return (-1);
				if (fstat(s, &sbuf) != -1)
					LogDev = sbuf.st_rdev;

			} else if (fstat(s, &sbuf) == -1 ||
			    LogDev != sbuf.st_rdev)
				return (-1);

			/* build the header */

			/* parse <pri> from msg */

			hdr.mid	= 1; /* 0 for kernal */
			/* sid, ltime, ttime, seq_no not used */

			hdr.pri = strtol(msg + 1, &msg_p, 10);
			if (msg + 1 == msg_p) {
				hdr.pri = (LOG_USER|LOG_INFO);
			} else {
				len -= msg_p - msg;
				msg = msg_p + 1;
			}
			hdr.flags = SL_CONSOLE;
			hdr.level = 0;

			ctl.maxlen = sizeof (struct log_ctl);
			ctl.len = sizeof (struct log_ctl);
			ctl.buf = (caddr_t)&hdr;
			dat.maxlen = MAXLINE;
			dat.len = len;
			if (dat.len > MAXLINE) {
				dat.len = MAXLINE;
				msg[MAXLINE - 1] = '\0';
			}
			dat.buf = msg;

			/* output the message to the local logger */
			if (_putmsg(s, &ctl, &dat, 0) == 0)
				return (0);
		}
		if (errno == N_AGAIN)
			errno = EWOULDBLOCK;
		else
			maperror();
	}
	return (a);
}


int
sendmsg(s, msg, flags)
	int	s;
	struct msghdr *msg;
	int	flags;
{
	int	a;
	if ((a = _sendmsg(s, msg, flags)) == -1) {
		if (errno == N_AGAIN)
			errno = EWOULDBLOCK;
		else
			maperror();
	}
	return (a);
}
