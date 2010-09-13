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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
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
#include <libintl.h>
#include <sys/isa_defs.h>

#ifdef SYSV
#define	bcopy(a, b, c)	memcpy((b), (a), (c))
#endif /* SYSV */

static int look_for_invite(CTL_RESPONSE *);
static CTL_RESPONSE swapresponse();


	/* see if the local daemon has a invitation for us */

int
check_local()
{
	CTL_RESPONSE response;

	/* the rest of msg was set up in get_names */

	msg.ctl_addr = ctl_addr;

	if (!look_for_invite(&response)) {

		/* we must be initiating a talk */

		return (0);
	}

	/*
	 * there was an invitation waiting for us,
	 * so connect with the other (hopefully waiting) party
	 */

	current_state = gettext("Waiting to connect with caller");

	response = swapresponse(response);
	while (connect(sockt, (struct sockaddr *)&response.addr,
		sizeof (response.addr)) != 0) {
		if (errno == ECONNREFUSED) {

			/*
			 * the caller gave up, but the invitation somehow
			 * was not cleared. Clear it and initiate an
			 * invitation. (We know there are no newer invitations,
			 * the talkd works LIFO.)
			 */

			ctl_transact(rem_machine_addr, msg, DELETE, &response);
			close(sockt);
			open_sockt();
			return (0);
		} else if (errno == EINTR) {

		/* we have returned from an interupt handler */
			continue;
		} else {
			p_error(gettext("Unable to connect with initiator"));
		}
	}

	return (1);
}

	/* look for an invitation on 'machine' */

static int
look_for_invite(response)
CTL_RESPONSE *response;
{
	current_state = gettext("Checking for invitation on caller's machine");

	ctl_transact(rem_machine_addr, msg, LOOK_UP, response);

	/*
	 * switch is for later options, such as multiple invitations
	 */

	switch (response->answer) {

	case SUCCESS:

		msg.id_num = response->id_num;
		return (1);

	default :
		/* there wasn't an invitation waiting for us */
		return (0);
	}
}

/*
 * heuristic to detect if need to reshuffle CTL_RESPONSE structure
 */

#if defined(_LITTLE_ENDIAN)
struct ctl_response_runrise {
	char type;
	char answer;
	short junk;
	int id_num;
	struct sockaddr_in addr;
};

static CTL_RESPONSE
swapresponse(rsp)
	CTL_RESPONSE rsp;
{
	struct ctl_response_runrise swaprsp;

	if (rsp.addr.sin_family != AF_INET) {
		bcopy(&rsp, &swaprsp, sizeof (CTL_RESPONSE));
		if (swaprsp.addr.sin_family == AF_INET) {
			rsp.addr = swaprsp.addr;
			rsp.type = swaprsp.type;
			rsp.answer = swaprsp.answer;
			rsp.id_num = swaprsp.id_num;
		}
	}
	return (rsp);
}
#endif

#if defined(_BIG_ENDIAN)
struct ctl_response_sun3 {
	char type;
	char answer;
	unsigned short id_num2;
	unsigned short id_num1;
	short sin_family;
	short sin_port;
	short sin_addr2;
	short sin_addr1;
};

static CTL_RESPONSE
swapresponse(rsp)
	CTL_RESPONSE rsp;
{
	struct ctl_response_sun3 swaprsp;

	if (rsp.addr.sin_family != AF_INET) {
		bcopy(&rsp, &swaprsp, sizeof (struct ctl_response_sun3));
		if (swaprsp.sin_family == AF_INET) {
			rsp.type = swaprsp.type;
			rsp.answer = swaprsp.answer;
			rsp.id_num = swaprsp.id_num1
				| (swaprsp.id_num2 << 16);
			rsp.addr.sin_family = swaprsp.sin_family;
			rsp.addr.sin_port = swaprsp.sin_port;
			rsp.addr.sin_addr.s_addr =
				(swaprsp.sin_addr2 << 16)| swaprsp.sin_addr1;
		}
	}
	return (rsp);
}
#endif
