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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Taken from 4.1.3 ypserv resolver code. */

/*
 * Send query to name server and wait for reply.
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>
#include <strings.h>
#include "nres.h"
#include "prnt.h"

int
nres_xmit(struct nres *tnr)
{
	char		*buf;
	int		buflen;
	int		v_circuit;
	ushort_t	len;

	struct iovec    iov[2];

	buf = tnr->question;
	buflen = tnr->question_len;

	prnt(P_INFO, "nres_xmit().\n");
	if (verbose && verbose_out) p_query((uchar_t *)buf);
	if (!(_res.options & RES_INIT))
		if (res_init() == -1) {
			return (-1);
		}
	v_circuit = (_res.options & RES_USEVC) || buflen > PACKETSZ;
	if (tnr->using_tcp)
		v_circuit = 1;
	if (v_circuit)
		tnr->using_tcp = 1;

	prnt(P_INFO, "this is retry %d.\n", tnr->retries);

	if (_res.nscount <= 0) {
		prnt(P_INFO, "nres_xmit -- no name servers\n");
		return (-1);
	}
	if (tnr->retries >= _res.retry) {
		prnt(P_INFO,
			"nres_xmit -- retries exausted %d.\n", _res.retry);
		return (-1);
	}
	if (tnr->current_ns >= _res.nscount) {
		tnr->current_ns = 0;
		tnr->retries = tnr->retries + 1;
	}
	tnr->nres_rpc_as.as_timeout_remain.tv_sec = (_res.retrans <<
						(tnr->retries)) / _res.nscount;
	tnr->nres_rpc_as.as_timeout_remain.tv_usec = 0;
	if (tnr->nres_rpc_as.as_timeout_remain.tv_sec < 1)
		tnr->nres_rpc_as.as_timeout_remain.tv_sec = 1;

	for (; tnr->current_ns < _res.nscount; tnr->current_ns++) {
		prnt(P_INFO,
		"Querying server (# %d) address = %s.\n", tnr->current_ns + 1,
			inet_ntoa(_res.nsaddr_list[tnr->current_ns].sin_addr));
		if (v_circuit) {

			/*
			 * Use virtual circuit.
			 */
			if (tnr->tcp_socket < 0) {
				tnr->tcp_socket = socket(AF_INET,
							SOCK_STREAM, 0);
				if (tnr->tcp_socket < 0) {
					prnt(P_ERR, "socket failed: %s.\n",
							strerror(errno));
					if (tnr->udp_socket < 0)
						return (-1);
				}
				if (connect(tnr->tcp_socket,
		(struct sockaddr *)&(_res.nsaddr_list[tnr->current_ns]),
					    sizeof (struct sockaddr)) < 0) {
					prnt(P_ERR, "connect failed: %s.\n",
							strerror(errno));
					(void) close(tnr->tcp_socket);
					tnr->tcp_socket = -1;
					continue;
				}
			}
			/*
			 * Send length & message
			 */
			len = htons((ushort_t)buflen);
			iov[0].iov_base = (caddr_t)&len;
			iov[0].iov_len = sizeof (len);
			iov[1].iov_base = tnr->question;
			iov[1].iov_len = tnr->question_len;
			if (writev(tnr->tcp_socket, iov, 2) !=
					sizeof (len) + buflen) {
				prnt(P_ERR, "write failed: %s.\n",
							strerror(errno));
				(void) close(tnr->tcp_socket);
				tnr->tcp_socket = -1;
				continue;
			}
			/* reply will come on tnr->tcp_socket */
		} else {
			/*
			 * Use datagrams.
			 */
			if (tnr->udp_socket < 0)
				tnr->udp_socket = socket(AF_INET,
							SOCK_DGRAM, 0);
			if (tnr->udp_socket < 0)
				return (-1);

			if (sendto(tnr->udp_socket, buf, buflen, 0,
			(struct sockaddr *)&_res.nsaddr_list[tnr->current_ns],
					sizeof (struct sockaddr)) != buflen) {
				prnt(P_ERR, "sendto failed: %s.\n",
							strerror(errno));
				continue;
			} else {
				if (tnr->retries == 0)
					return (0);
			}
		}
	}
	return (0);
}
