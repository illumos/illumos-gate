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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include "nres.h"
#include "prnt.h"


int
nres_rcv(struct nres *tnr)
{
	register int    n;
	int		resplen;
	ushort_t	len;
	char		*cp;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	HEADER		*hp = (HEADER *)tnr->question;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	HEADER		*anhp = (HEADER *)tnr->answer;
	int		s;
	int		truncated = 0;
	char		junk[512];
	if (tnr->using_tcp == 0) {
		s = tnr->udp_socket;

		if ((resplen = recv(s, tnr->answer, MAXPACKET, 0)) <= 0) {
			prnt(P_ERR, "recv failed: %s.\n", strerror(errno));
			return (-1);
		}
		if (hp->id != anhp->id) {
			/*
			 * response from old query, ignore it
			 */
			prnt(P_INFO, "old answer.\n");
			if (verbose && verbose_out)
				p_query((uchar_t *)tnr->answer);
			return (0);	/* wait again */
		}
		if (!(_res.options & RES_IGNTC) && anhp->tc) {
			/*
			 * get rest of answer
			 */
			prnt(P_INFO, "truncated answer..\n");
			(void) close(tnr->udp_socket);
			tnr->udp_socket = -1;
			tnr->using_tcp = 1;
			return (-1);
		}
		tnr->answer_len = resplen;
		return (1);
	} else {
		/* tcp case */
		s = tnr->tcp_socket;
		/*
		 * Receive length & response
		 */
		cp = tnr->answer;
		len = sizeof (short);
		while (len != 0 && (n = read(s, (char *)cp, (int)len)) > 0) {
			cp += n;
			len -= n;
		}
		if (n <= 0) {
			prnt(P_ERR, "read failed: %s.\n", strerror(errno));
			(void) close(s);
			tnr->tcp_socket = -1;
			return (-1);
		}
		cp = tnr->answer;
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		if ((resplen = ntohs(*(ushort_t *)cp)) > MAXPACKET) {
			prnt(P_INFO, "response truncated.\n");
			len = MAXPACKET;
			truncated = 1;
		} else
			len = resplen;
		while (len != 0 && (n = read(s, (char *)cp, (int)len)) > 0) {
			cp += n;
			len -= n;
		}
		if (n <= 0) {
			prnt(P_ERR, "read failed: %s.\n", strerror(errno));
			(void) close(s);
			tnr->tcp_socket = -1;
			return (-1);
		}
		if (truncated) {
			/*
			 * Flush rest of answer so connection stays in synch.
			 */
			anhp->tc = 1;
			len = resplen - MAXPACKET;
			while (len != 0) {
				n = (len > sizeof (junk) ? sizeof (junk) : len);
				if ((n = read(s, junk, n)) > 0)
					len -= n;
				else
					break;
			}
		}
		if (hp->id != anhp->id) {
			/*
			 * response from old query, ignore it
			 */
			prnt(P_INFO, "old answer.\n");
			if (verbose && verbose_out)
				p_query((uchar_t *)tnr->answer);
			return (0);	/* wait again */

		}
		tnr->answer_len = resplen;
		return (1);
	}
}
