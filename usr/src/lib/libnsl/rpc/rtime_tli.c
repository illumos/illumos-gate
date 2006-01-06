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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * get time from remote machine
 *
 * gets time, obtaining value from host
 * on the (udp, tcp)/time tli connection. Since timeserver returns
 * with time of day in seconds since Jan 1, 1900, must
 * subtract seconds before Jan 1, 1970 to get
 * what unix uses.
 */
#include "mt.h"
#include <rpc/rpc.h>
#include <errno.h>
#include <sys/poll.h>
#include <rpc/nettype.h>
#include <netdir.h>
#include <stdio.h>

extern int __rpc_timeval_to_msec();

#ifdef DEBUG
#define	debug(msg)	t_error(msg)
#else
#define	debug(msg)
#endif

#define	NYEARS	(1970 - 1900)
#define	TOFFSET ((uint_t)60*60*24*(365*NYEARS + (NYEARS/4)))

/*
 * This is based upon the internet time server, but it contacts it by
 * using TLI instead of socket.
 */
int
rtime_tli(char *host, struct timeval *timep, struct timeval *timeout)
{
	uint32_t thetime;
	int flag;
	struct nd_addrlist *nlist = NULL;
	struct nd_hostserv rpcbind_hs;
	struct netconfig *nconf = NULL;
	int foundit = 0;
	int fd = -1;

	nconf = __rpc_getconfip(timeout == NULL ? "tcp" : "udp");
	if (nconf == NULL)
		goto error;

	if ((fd = t_open(nconf->nc_device, O_RDWR, NULL)) == -1) {
		debug("open");
		goto error;
	}
	if (t_bind(fd, NULL, NULL) < 0) {
		debug("bind");
		goto error;
	}

	/* Get the address of the rpcbind */
	rpcbind_hs.h_host = host;
	rpcbind_hs.h_serv = "time";
	/* Basically get the address of the remote machine on IP */
	if (netdir_getbyname(nconf, &rpcbind_hs, &nlist))
		goto error;

	if (nconf->nc_semantics == NC_TPI_CLTS) {
		struct t_unitdata tu_data;
		struct pollfd pfd;
		int res;
		int msec;

		tu_data.addr = *nlist->n_addrs;
		tu_data.udata.buf = (char *)&thetime;
		tu_data.udata.len = (uint_t)sizeof (thetime);
		tu_data.udata.maxlen = tu_data.udata.len;
		tu_data.opt.len = 0;
		tu_data.opt.maxlen = 0;
		if (t_sndudata(fd, &tu_data) == -1) {
			debug("udp");
			goto error;
		}
		pfd.fd = fd;
		pfd.events = POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND;

		msec = __rpc_timeval_to_msec(timeout);
		do {
			res = poll(&pfd, 1, msec);
		} while (res < 0);
		if ((res <= 0) || (pfd.revents & POLLNVAL))
			goto error;
		if (t_rcvudata(fd, &tu_data, &flag) < 0) {
			debug("udp");
			goto error;
		}
		foundit = 1;
	} else {
		struct t_call sndcall;

		sndcall.addr = *nlist->n_addrs;
		sndcall.opt.len = sndcall.opt.maxlen = 0;
		sndcall.udata.len = sndcall.udata.maxlen = 0;

		if (t_connect(fd, &sndcall, NULL) == -1) {
			debug("tcp");
			goto error;
		}
		if (t_rcv(fd, (char *)&thetime, (uint_t)sizeof (thetime), &flag)
				!= (uint_t)sizeof (thetime)) {
			debug("tcp");
			goto error;
		}
		foundit = 1;
	}

	thetime = ntohl(thetime);
	timep->tv_sec = thetime - TOFFSET;
	timep->tv_usec = 0;

error:
	if (nconf) {
		(void) freenetconfigent(nconf);
		if (fd != -1) {
			(void) t_close(fd);
			if (nlist)
				netdir_free((char *)nlist, ND_ADDRLIST);
		}
	}
	return (foundit);
}
