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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
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

#include "talk_ctl.h"
#include <sys/time.h>
#include <libintl.h>

#define	CTL_WAIT	2
	/* the amount of time to wait for a response, in seconds */


/*
 * SOCKDGRAM is unreliable, so we must repeat messages if we have
 * not recieved an acknowledgement within a reasonable amount of time
 */

void
ctl_transact(target, msg, type, response)
struct in_addr target;
CTL_MSG msg;
int type;
CTL_RESPONSE *response;
{
	struct sockaddr junk;
	int read_mask;
	int ctl_mask;
	int nready;
	int cc;
	socklen_t junk_size;
	struct timeval wait;

	wait.tv_sec = CTL_WAIT;
	wait.tv_usec = 0;

	msg.type = type;

	daemon_addr.sin_addr = target;
	daemon_addr.sin_port = daemon_port;

	ctl_mask = 1 << ctl_sockt;

	/*
	 * keep sending the message until a response of the right
	 * type is obtained
	 */

	do {
		/* keep sending the message until a response is obtained */

		do {
			cc = sendto(ctl_sockt,
				(char *)&msg, sizeof (CTL_MSG), 0,
			(struct sockaddr *)&daemon_addr, sizeof (daemon_addr));

			if (cc != sizeof (CTL_MSG)) {
				if (errno == EINTR) {
			/* we are returning from an interupt */
					continue;
				} else {
					p_error(
				gettext("Error on write to talk daemon"));
				}
			}

			read_mask = ctl_mask;

			while ((nready = select(32, (fd_set *)&read_mask,
				0, 0, &wait)) < 0) {
			if (errno == EINTR) {
			/* we are returning from an interupt */
				continue;
			} else {
				p_error(
			gettext("Error on waiting for response from daemon"));
			}
		}
	} while (nready == 0);

	/*
	 * keep reading while there are queued messages
	 * (this is not necessary, it just saves extra
	 * request/acknowledgements being sent)
	 */

	do {

		junk_size = (socklen_t)sizeof (junk);
		cc = recvfrom(ctl_sockt, (char *)response,
			sizeof (CTL_RESPONSE), 0, &junk, &junk_size);
		if (cc < 0) {
			if (errno == EINTR) {
				continue;
			}
			p_error(gettext("Error on read from talk daemon"));
		}

		read_mask = ctl_mask;

		/* an immediate poll */

		timerclear(&wait);
		nready = select(32, (fd_set *)&read_mask, 0, 0, &wait);

	} while (nready > 0 && response->type != type);

	} while (response->type != type);
}
