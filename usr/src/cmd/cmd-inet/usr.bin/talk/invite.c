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
 * Copyright 1994 Sun Microsystems, Inc.  All rights reserved.
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
/*
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "talk_ctl.h"
#include <sys/time.h>
#include <signal.h>
#include <setjmp.h>
#include <libintl.h>

#ifdef SYSV
#define	signal(s, f)	sigset(s, f)
#endif /* SYSV */

	/*
	 * There wasn't an invitation waiting, so send a request containing
	 * our socket address to the remote talk daemon so it can invite
	 * the remote.
	 */

static int local_id, remote_id;

	/*
	 * the msg.id's for the invitations
	 * on the local and remote machines.
	 * These are used to delete the invitations.
	 */

static jmp_buf	invitebuf;

static void re_invite();
static void announce_invite();

void
invite_remote()
{
	int new_sockt;
	struct itimerval itimer;
	CTL_RESPONSE response;

	itimer.it_value.tv_sec = RING_WAIT;
	itimer.it_value.tv_usec = 0;
	itimer.it_interval = itimer.it_value;

	if (listen(sockt, 5) != 0) {
		p_error(gettext("Error on attempt to listen for caller"));
	}

	msg.addr = my_addr;
	msg.id_num = -1;		/* an impossible id_num */

	invitation_waiting = 1;

	announce_invite();

	/*
	 * shut off the automatic messages for a while,
	 * so we can use the interupt timer to resend the invitation
	 */

	end_msgs();
	setitimer(ITIMER_REAL, &itimer, (struct itimerval *)0);
	message(gettext("Waiting for your party to respond"));
	signal(SIGALRM, re_invite);
	(void) setjmp(invitebuf);

	while ((new_sockt = accept(sockt, 0, 0)) < 0) {
		if (errno != EINTR) {
			p_error(gettext("Unable to connect with your party"));
		} else {
		/* we just returned from a interupt, keep trying */
			continue;
		}
	}

	close(sockt);
	sockt = new_sockt;

	/*
	 * have the daemons delete the invitations now that we have connected.
	 */

	current_state = strdup(gettext("Waiting for your party to respond"));
	start_msgs();

	msg.id_num = local_id;
	ctl_transact(my_machine_addr, msg, DELETE, &response);
	msg.id_num = remote_id;
	ctl_transact(rem_machine_addr, msg, DELETE, &response);
	invitation_waiting = 0;
}

	/* routine called on interupt to re-invite the callee */

static void
re_invite()
{
	message(gettext("Ringing your party again"));
	current_line++;
	/* force a re-announce */
	msg.id_num = remote_id + 1;
	announce_invite();
	longjmp(invitebuf, 1);
}

	/* transmit the invitation and process the response */

static void
announce_invite()
{
	CTL_RESPONSE response;

	current_state =
		gettext("Trying to connect to your party's talk daemon");

	ctl_transact(rem_machine_addr, msg, ANNOUNCE, &response);
	remote_id = response.id_num;

	if (response.answer != SUCCESS) {

		switch (response.answer) {

			case NOT_HERE :
			message(gettext("Your party is not logged on"));
			break;

			case MACHINE_UNKNOWN :
			message(
			gettext("Target machine does not recognize us"));
			break;

			case UNKNOWN_REQUEST :
			message(
			gettext("Target machine can not handle remote talk"));
			break;

			case FAILED :
			message(
		gettext("Target machine is too confused to talk to us"));
			break;

			case PERMISSION_DENIED :
			message(gettext("Your party is refusing messages"));
			break;
		}

		quit();
	}

	/* leave the actual invitation on my talk daemon */

	ctl_transact(my_machine_addr, msg, LEAVE_INVITE, &response);
	local_id = response.id_num;
}

void
send_delete()
{

	/* tell the daemon to remove your invitation */

	msg.type = DELETE;

	/*
	 * this is just a extra clean up, so just send it
	 * and don't wait for an answer
	 */

	msg.id_num = remote_id;
	daemon_addr.sin_addr = rem_machine_addr;
	if (sendto(ctl_sockt, (char *)&msg, sizeof (CTL_MSG), 0,
		(struct sockaddr *)&daemon_addr,
			sizeof (daemon_addr)) != sizeof (CTL_MSG)) {
		perror(gettext("send_delete remote"));
	}

	msg.id_num = local_id;
	daemon_addr.sin_addr = my_machine_addr;
	if (sendto(ctl_sockt, (char *)&msg, sizeof (CTL_MSG), 0,
		(struct sockaddr *)&daemon_addr,
			sizeof (daemon_addr)) != sizeof (CTL_MSG)) {
		perror(gettext("send_delete local"));
	}
}
