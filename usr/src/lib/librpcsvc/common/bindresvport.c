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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * XXX This routine should be changed to use
 * ND_CHECK_RESERVED_PORT and ND_SET_RESERVED_PORT
 * which can be invoked via netdir_options.
 */
#include <stdio.h>
#include <rpc/rpc.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <rpc/nettype.h>
#include <stropts.h>
#include <string.h>
#include <tiuser.h>
#include <unistd.h>

#define	STARTPORT 600
#define	ENDPORT (IPPORT_RESERVED - 1)
#define	NPORTS	(ENDPORT - STARTPORT + 1)

/*
 * The argument is a client handle for a UDP connection.
 * Unbind its transport endpoint from the existing port
 * and rebind it to a reserved port.
 * On failure, the client handle can be unbound even if it
 * was previously bound.  Callers should destroy the client
 * handle after a failure.
 */
int
__clnt_bindresvport(cl)
	CLIENT *cl;
{
	int fd;
	int res;
	short port;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	extern int errno;
	/* extern int t_errno; */
	struct t_bind *tbind, *tres;
	int i;
	bool_t	ipv6_fl = FALSE;
	struct netconfig *nconf;

	/* make sure it's a UDP connection */
	nconf = getnetconfigent(cl->cl_netid);
	if (nconf == NULL)
		return (-1);
	if ((nconf->nc_semantics != NC_TPI_CLTS) ||
		(strcmp(nconf->nc_protofmly, NC_INET) &&
		strcmp(nconf->nc_protofmly, NC_INET)) ||
		strcmp(nconf->nc_proto, NC_UDP)) {
		freenetconfigent(nconf);
		return (0);	/* not udp - don't need resv port */
	}
	if (strcmp(nconf->nc_protofmly, NC_INET6) == 0)
		ipv6_fl = TRUE;
	freenetconfigent(nconf);

	if (!clnt_control(cl, CLGET_FD, (char *)&fd)) {
		return (-1);
	}

	/* If fd is already bound - unbind it */
	if (t_getstate(fd) != T_UNBND) {
		while ((t_unbind(fd) < 0) && (t_errno == TLOOK)) {
			/*
			 * If there is a message queued to this descriptor,
			 * remove it.
			 */
			struct strbuf ctl[1], data[1];
			char ctlbuf[sizeof (union T_primitives) + 32];
			char databuf[256];
			int flags;

			ctl->maxlen = sizeof (ctlbuf);
			ctl->buf = ctlbuf;
			data->maxlen = sizeof (databuf);
			data->buf = databuf;
			flags = 0;
			if (getmsg(fd, ctl, data, &flags) < 0)
				return (-1);

		}
		if (t_getstate(fd) != T_UNBND)
			return (-1);
	}

	tbind = (struct t_bind *)t_alloc(fd, T_BIND, T_ADDR);
	if (tbind == NULL) {
		if (t_errno == TBADF)
			errno = EBADF;
		return (-1);
	}
	tres = (struct t_bind *)t_alloc(fd, T_BIND, T_ADDR);
	if (tres == NULL) {
		(void) t_free((char *)tbind, T_BIND);
		return (-1);
	}

	(void) memset((char *)tbind->addr.buf, 0, tbind->addr.len);
	/* warning: this sockaddr_in is truncated to 8 bytes */

	if (ipv6_fl == TRUE) {
		sin6 = (struct sockaddr_in6 *)tbind->addr.buf;
		sin6->sin6_family = AF_INET6;
	} else {
		sin = (struct sockaddr_in *)tbind->addr.buf;
		sin->sin_family = AF_INET;
	}

	tbind->qlen = 0;
	tbind->addr.len = tbind->addr.maxlen;

	/*
	 * Need to find a reserved port in the interval
	 * STARTPORT - ENDPORT.  Choose a random starting
	 * place in the interval based on the process pid
	 * and sequentially search the ports for one
	 * that is available.
	 */
	port = (getpid() % NPORTS) + STARTPORT;

	for (i = 0; i < NPORTS; i++) {
		sin->sin_port = htons(port++);
		if (port > ENDPORT)
			port = STARTPORT;
		/*
		 * Try to bind to the requested address.  If
		 * the call to t_bind succeeds, then we need
		 * to make sure that the address that we bound
		 * to was the address that we requested.  If it
		 * was, then we are done.  If not, we fake an
		 * EADDRINUSE error by setting res, t_errno,
		 * and errno to indicate that a bind failure
		 * occurred.  Otherwise, if the t_bind call
		 * failed, we check to see whether it makes
		 * sense to continue trying to t_bind requests.
		 */
		res = t_bind(fd, tbind, tres);
		if (res == 0) {
			if (memcmp(tbind->addr.buf, tres->addr.buf,
					(int)tres->addr.len) == 0)
				break;
			(void) t_unbind(fd);
			res = -1;
			t_errno = TSYSERR;
			errno = EADDRINUSE;
		} else if (t_errno != TSYSERR || errno != EADDRINUSE) {
			if (t_errno == TACCES)
				errno = EACCES;
			break;
		}
	}

	(void) t_free((char *)tbind, T_BIND);
	(void) t_free((char *)tres,  T_BIND);
	return (res);
}
