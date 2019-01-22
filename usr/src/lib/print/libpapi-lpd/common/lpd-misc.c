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
 *
 */

/* $Id: lpd-misc.c 155 2006-04-26 02:34:54Z ktou $ */

#define	__EXTENSIONS__	/* for strtok_r() */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <errno.h>
#include <wait.h>
#include <stropts.h>
#include <papi_impl.h>

#include <config-site.h>

char *
fdgets(char *buf, size_t len, int fd)
{
	char	tmp;
	int	count = 0;

	memset(buf, 0, len);
	while ((count < len) && (read(fd, &tmp, 1) > 0))
		if ((buf[count++] = tmp) == '\n') break;

	if (count != 0)
		return (buf);
	return (NULL);
}

char *
queue_name_from_uri(uri_t *uri)
{
	char *result = NULL;

	if ((uri != NULL) && (uri->path != NULL)) {
		char *ptr = strrchr(uri->path, '/');

		if (ptr == NULL)
			result = uri->path;
		else
			result = ++ptr;
	}

	return (result);
}

static int
recvfd(int sockfd)
{
	int fd = -1;
#if defined(sun) && defined(unix) && defined(I_RECVFD)
	struct strrecvfd recv_fd;

	memset(&recv_fd, 0, sizeof (recv_fd));
	if (ioctl(sockfd, I_RECVFD, &recv_fd) == 0)
		fd = recv_fd.fd;
#else
	struct iovec    iov[1];
	struct msghdr   msg;

#ifdef CMSG_DATA
	struct cmsghdr cmp[1];
	char buf[24];	/* send/recv 2 byte protocol */

	memset(buf, 0, sizeof (buf));

	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof (buf);

	msg.msg_control = cmp;
	msg.msg_controllen = sizeof (struct cmsghdr) + sizeof (int);
#else
	iov[0].iov_base = NULL;
	iov[0].iov_len = 0;
	msg.msg_accrights = (caddr_t)&fd;
	msg.msg_accrights = sizeof (fd);
#endif
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	if (recvmsg(sockfd, &msg, 0) < 0)
		fd = -1;
#ifdef CMSG_DATA
	else
		fd = * (int *)CMSG_DATA(cmp);
#endif
#endif
	return (fd);
}

int
lpd_open(service_t *svc, char type, char **args, int timeout)
{
	int ac, rc = -1, fds[2];
	pid_t pid;
	char *av[64], *tmp, buf[BUFSIZ];

	if ((svc == NULL) || (svc->uri == NULL))
		return (-1);

#ifndef SUID_LPD_PORT
#define	SUID_LPD_PORT "/usr/lib/print/lpd-port"
#endif

	av[0] = SUID_LPD_PORT;
	ac = 1;

	/* server */
	av[ac++] = "-H";
	av[ac++] = svc->uri->host;

	/* timeout */
	if (timeout > 0) {
		snprintf(buf, sizeof (buf), "%d", timeout);
		av[ac++] = "-t";
		av[ac++] = strdup(buf);
	}

	/* operation */
	snprintf(buf, sizeof (buf), "-%c", type);
	av[ac++] = buf;

	/* queue */
	if (svc->uri->path == NULL) {
		tmp = "";
	} else {
		if ((tmp = strrchr(svc->uri->path, '/')) == NULL)
			tmp = svc->uri->path;
		else
			tmp++;
	}
	av[ac++] = tmp;

	/* args */
	if (args != NULL)
		while ((*args != NULL) && (ac < 62))
			av[ac++] = *args++;

	av[ac++] = NULL;

#if defined(sun) && defined(unix) && defined(I_RECVFD)
	pipe(fds);
#else
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
#endif

	switch (pid = fork()) {
	case -1:	/* failed */
		break;
	case 0:	 /* child */
		dup2(fds[1], 1);
		execv(av[0], &av[0]);
		perror("exec");
		exit(1);
		break;
	default: {	/* parent */
		int err, status = 0;

		while ((waitpid(pid, &status, 0) < 0) && (errno == EINTR))
			;
		errno = WEXITSTATUS(status);

		if (errno == 0)
			rc = recvfd(fds[0]);

		err = errno;
		close(fds[0]);
		close(fds[1]);
		errno = err;
		}
	}

	return (rc);
}
