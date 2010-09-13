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
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 * All Rights Reserved.
 */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California.
 * All Rights Reserved.
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * process.c handles the requests, which can be of three types:
 *
 * ANNOUNCE - announce to a user that a talk is wanted
 *
 * LEAVE_INVITE - insert the request into the table
 *
 * LOOK_UP - look up to see if a request is waiting in
 * in the table for the local user
 *
 * DELETE - delete invitation
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <utmpx.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "talkd_impl.h"

static void do_announce(CTL_MSG *request, CTL_RESPONSE *response);
static int find_user(char *name, char *tty);

void
process_request(CTL_MSG *request, CTL_RESPONSE *response)
{
	CTL_MSG *ptr;

	response->type = request->type;
	response->id_num = 0;

	/*
	 * Check if any of the strings within the request structure aren't
	 * NUL terminated, and if so don't bother processing the request
	 * further.
	 */
	if ((memchr(request->l_name, '\0', sizeof (request->l_name)) == NULL) ||
	    (memchr(request->r_name, '\0', sizeof (request->r_name)) == NULL) ||
	    (memchr(request->r_tty, '\0', sizeof (request->r_tty)) == NULL)) {
		response->answer = FAILED;
		openlog("talk", 0, LOG_AUTH);
		syslog(LOG_CRIT, "malformed talk request\n");
		closelog();
		return;
	}

	switch (request->type) {

	    case ANNOUNCE :

		do_announce(request, response);
		break;

	    case LEAVE_INVITE :

		ptr = find_request(request);
		if (ptr != NULL) {
			response->id_num = ptr->id_num;
			response->answer = SUCCESS;
		} else {
			insert_table(request, response);
		}
		break;

	    case LOOK_UP :

		ptr = find_match(request);
		if (ptr != NULL) {
			response->id_num = ptr->id_num;
			response->addr = ptr->addr;
			response->answer = SUCCESS;
		} else {
			response->answer = NOT_HERE;
		}
		break;

	    case DELETE :

		response->answer = delete_invite(request->id_num);
		break;

	    default :

		response->answer = UNKNOWN_REQUEST;
		break;
	}
}

static void
do_announce(CTL_MSG *request, CTL_RESPONSE *response)
{
	struct hostent *hp;
	CTL_MSG *ptr;
	int result;

	/*
	 * See if the user is logged.
	 */
	result = find_user(request->r_name, request->r_tty);
	if (result != SUCCESS) {
		response->answer = result;
		return;
	}

	hp = gethostbyaddr((const char *)&request->ctl_addr.sin_addr,
	    sizeof (struct in_addr), AF_INET);
	if (hp == NULL) {
		response->answer = MACHINE_UNKNOWN;
		return;
	}

	ptr = find_request(request);
	if (ptr == NULL) {
		insert_table(request, response);
		response->answer = announce(request, hp->h_name);
	} else if (request->id_num > ptr->id_num) {
		/*
		 * This is an explicit re-announce, so update the id_num
		 * field to avoid duplicates and re-announce the talk.
		 */
		ptr->id_num = response->id_num = new_id();
		response->answer = announce(request, hp->h_name);
	} else {
		/* a duplicated request, so ignore it */
		response->id_num = ptr->id_num;
		response->answer = SUCCESS;
	}
}

/*
 * Search utmp for the local user.
 */

static int
find_user(char *name, char *tty)
{
	struct utmpx *ubuf;
	int tfd;
	char dev[MAXPATHLEN];
	struct stat stbuf;
	int problem = NOT_HERE;

	setutxent();		/* reset the utmpx file */

	while (ubuf = getutxent()) {
		if (ubuf->ut_type == USER_PROCESS &&
		    strncmp(ubuf->ut_user, name, sizeof (ubuf->ut_user)) == 0) {
			/*
			 * Check if this entry is really a tty.
			 */
			(void) snprintf(dev, sizeof (dev), "/dev/%.*s",
			    sizeof (ubuf->ut_line), ubuf->ut_line);
			if ((tfd = open(dev, O_WRONLY|O_NOCTTY)) == -1) {
				continue;
			}
			if (!isatty(tfd)) {
				(void) close(tfd);
				openlog("talk", 0, LOG_AUTH);
				syslog(LOG_CRIT, "%.*s in utmp is not a tty\n",
				    sizeof (ubuf->ut_line), ubuf->ut_line);
				closelog();
				continue;
			}
			if (*tty == '\0') {
				/*
				 * No particular tty was requested.
				 */
				if (fstat(tfd, &stbuf) < 0 ||
				    (stbuf.st_mode&020) == 0) {
					(void) close(tfd);
					problem = PERMISSION_DENIED;
					continue;
				}
				(void) close(tfd);
				(void) strlcpy(tty, ubuf->ut_line, TTY_SIZE);
				endutxent();	/* close the utmpx file */
				return (SUCCESS);
			}
			(void) close(tfd);
			if (strcmp(ubuf->ut_line, tty) == 0) {
				endutxent();	/* close the utmpx file */
				return (SUCCESS);
			}
		}
	}

	endutxent();		/* close the utmpx file */
	return (problem);
}
