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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
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

#include	<unistd.h>
#include	<stdlib.h>
#include	<stdio.h>
#include	<fcntl.h>
#include	<sys/types.h>
#include	<sys/wait.h>
#include	<string.h>
#include	<memory.h>
#include	<utmpx.h>
#include	<security/pam_appl.h>

#include	"sac.h"
#include	"tmextern.h"

extern	char	*lastname();

/*
 * account - create a utmpx record for service
 *
 */

int
account(line)
char	*line;
{
	struct utmpx utmpx;			/* prototype utmpx entry */
	struct utmpx *up = &utmpx;		/* and a pointer to it */

	(void) memset(up, '\0', sizeof (utmpx));
	up->ut_user[0] = '.';
	(void) strncpy(&up->ut_user[1], Tag, sizeof (up->ut_user)-1);
	(void) strncpy(up->ut_line, lastname(line), sizeof (up->ut_line));
	up->ut_pid = getpid();
	up->ut_type = USER_PROCESS;
	up->ut_id[0] = 't';
	up->ut_id[1] = 'm';
	up->ut_id[2] = SC_WILDC;
	up->ut_id[3] = SC_WILDC;
	up->ut_exit.e_termination = 0;
	up->ut_exit.e_exit = 0;
	(void) time(&up->ut_tv.tv_sec);
	if (makeutx(up) == NULL) {
		log("makeutx for pid %d failed", up->ut_pid);
		return (-1);
	}
	return (0);
}

/*
 * checkut_line	- check if a login is active on the requested device
 */
int
checkut_line(char *line)
{
	struct utmpx *u;
	char buf[33], ttyn[33];
	int rvalue = 0;
	pid_t ownpid = getpid();

	(void) strncpy(buf, lastname(line), sizeof (u->ut_line));
	buf[sizeof (u->ut_line)] = '\0';

	setutxent();
	while ((u = getutxent()) != NULL) {
		if (u->ut_pid == ownpid) {
			if (u->ut_type == USER_PROCESS) {
				strncpy(ttyn, u->ut_line, sizeof (u->ut_line));
				ttyn[sizeof (u->ut_line)] = '\0';
				if (strcmp(buf, ttyn) == 0) {
					rvalue = 1;
					break;
				}
			}
		}
	}
	endutxent();

	return (rvalue);
}


void
cleanut(pid, status)
	pid_t	pid;
	int	status;
{
	pam_handle_t *pamh;
	struct utmpx *up;
	struct utmpx ut;
	char user[33], ttyn[33], rhost[258];

	setutxent();
	while (up = getutxent()) {
		if (up->ut_pid == pid) {
			if (up->ut_type == DEAD_PROCESS) {
				/* Cleaned up elsewhere. */
				break;
			}

			strncpy(user, up->ut_user, sizeof (up->ut_user));
			user[sizeof (up->ut_user)] = '\0';
			strncpy(ttyn, up->ut_line, sizeof (up->ut_line));
			ttyn[sizeof (up->ut_line)] = '\0';
			strncpy(rhost, up->ut_host, sizeof (up->ut_host));
			rhost[sizeof (up->ut_host)] = '\0';

			if (pam_start("ttymon", user, NULL, &pamh)
							== PAM_SUCCESS) {
				(void) pam_set_item(pamh, PAM_TTY, ttyn);
				(void) pam_set_item(pamh, PAM_RHOST, rhost);
				(void) pam_close_session(pamh, 0);
				(void) pam_end(pamh, PAM_SUCCESS);
			}


			up->ut_type = DEAD_PROCESS;
			up->ut_exit.e_termination = WTERMSIG(status);
			up->ut_exit.e_exit = WEXITSTATUS(status);
			(void) time(&up->ut_tv.tv_sec);

			if (modutx(up) == NULL) {
				/*
				 * Since modutx failed we'll
				 * write out the new entry
				 * ourselves.
				 */
				(void) pututxline(up);
				updwtmpx("wtmpx", up);
			}
			break;
		}
	}
	endutxent();
}

/*
 * getty_account	- This is a copy of old getty account routine.
 *			- This is only called if ttymon is invoked as getty.
 *			- It tries to find its own INIT_PROCESS entry in utmpx
 *			- and change it to LOGIN_PROCESS
 */
void
getty_account(line)
char *line;
{
	pid_t ownpid;
	struct utmpx *u;

	ownpid = getpid();

	setutxent();
	while ((u = getutxent()) != NULL) {

		if (u->ut_type == INIT_PROCESS && u->ut_pid == ownpid) {
			(void) strncpy(u->ut_line, lastname(line),
				sizeof (u->ut_line));
			(void) strncpy(u->ut_user, "LOGIN",
					sizeof (u->ut_user));
			u->ut_type = LOGIN_PROCESS;

			/* Write out the updated entry. */
			(void) pututxline(u);
			break;
		}
	}

	/* create wtmpx entry also */
	if (u != NULL)
		updwtmpx("/etc/wtmpx", u);

	endutxent();
}
