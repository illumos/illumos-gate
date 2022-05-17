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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include "ttymon.h"
#include "tmextern.h"
#include "sac.h"

/*
 *	openpid	- open the pid and put ttymon's pid in it
 *		- put an advisory lock on the file
 *		- to prevent another instance of ttymon in same directory
 *		- SAC also makes use of the lock
 *		- fd 0 is reserved for pid file
 */
void
openpid(void)
{
	char lockbuf[16];	/* large enough for a PID string */

	(void) close(0);
	/* open for read first, otherwise, may delete the pid already there */
	if ((Lckfd = open(PIDFILE, O_RDONLY)) != -1) {
		if (lockf(Lckfd, F_TEST, 0L) == -1)
			fatal("pid file is locked. ttymon may already be "
			    "running!");
		(void) close(Lckfd);
	}

	if ((Lckfd = open(PIDFILE, O_WRONLY|O_CREAT|O_TRUNC, 0644)) != 0)
		fatal("open pid file failed: %s", strerror(errno));

	if (lockf(Lckfd, F_LOCK, 0L) == -1)
		fatal("lock pid file failed: %s", strerror(errno));

	(void) snprintf(lockbuf, sizeof (lockbuf), "%ld", getpid());
	(void) write(Lckfd, lockbuf, strlen(lockbuf) + 1);
#ifdef	DEBUG
	log("fd(pid)\t = %d", Lckfd);
#endif
}

/*
 * openpipes() -- open pmpipe and sacpipe to communicate with SAC
 *	       -- Pfd, Sfd are global file descriptors for pmpipe, sacpipe
 */

void
openpipes(void)
{
	Sfd = open(SACPIPE, O_WRONLY);
	if (Sfd < 0)
		fatal("open sacpipe failed: %s", strerror(errno));

	Pfd = open(PMPIPE, O_RDWR|O_NONBLOCK);
	if (Pfd < 0)
		fatal("open pmpipe failed: %s", strerror(errno));

#ifdef	DEBUG
	log("fd(sacpipe)\t = %d", Sfd);
	log("fd(pmpipe)\t = %d", Pfd);
#endif
}

/*
 * remove_env(env) - remove an environment variable from the environment
 */
static	void
remove_env(char *env)
{
	char	**p;
	char	**rp = NULL;

	p = environ;
	if (p == NULL)
		return;
	while (*p) {
		if (strncmp(*p, env, strlen(env)) == 0)
			rp = p;
		p++;
	}
	if (rp) {
		*rp = *--p;
		*p = NULL;
	}
}

/*
 * get_environ() -- get env variables PMTAG, ISTATE
 *		 -- set global variables Tag, State
 */

void
get_environ(void)
{
	if ((Tag = getenv("PMTAG")) == NULL)
		fatal("PMTAG is missing");

	if ((Istate = getenv("ISTATE")) == NULL)
		fatal("ISTATE is missing");

	State = (strcmp(Istate, "enabled") == 0) ? PM_ENABLED : PM_DISABLED;

	/*
	 * remove the environment variables so they will not
	 * be passed to the children
	 */
	remove_env("ISTATE");
	remove_env("PMTAG");
}

/*
 * sacpoll	- the event handler when sac event is posted
 */
void
sacpoll(void)
{
	int	ret;
	char	oldState;
	struct	sacmsg sacmsg;
	struct	pmmsg pmmsg;
	sigset_t	cset;
	sigset_t	tset;

#ifdef	DEBUG
	debug("in sacpoll");
#endif

	/* we don't want to be interrupted by sigchild now */
	(void) sigprocmask(SIG_SETMASK, NULL, &cset);
	tset = cset;
	(void) sigaddset(&tset, SIGCLD);
	(void) sigprocmask(SIG_SETMASK, &tset, NULL);

	/*
	 *	read sac messages, one at a time until no message
	 *	is left on the pipe.
	 *	the pipe is open with O_NONBLOCK, read will return -1
	 *	and errno = EAGAIN if nothing is on the pipe
	 */
	for (;;) {

		ret = read(Pfd, &sacmsg, sizeof (sacmsg));
		if (ret < 0) {
			switch (errno) {
			case EAGAIN:
				/* no more data on the pipe */
				(void) sigprocmask(SIG_SETMASK, &cset, NULL);
				return;
			case EINTR:
				break;
			default:
				fatal("pmpipe read failed: %s",
				    strerror(errno));
				break;  /*NOTREACHED*/
			}
		} else if (ret == 0) {
			/* no more data on the pipe */
			(void) sigprocmask(SIG_SETMASK, &cset, NULL);
			return;
		} else {
			pmmsg.pm_size = 0;
			(void) strcpy(pmmsg.pm_tag, Tag);
			pmmsg.pm_maxclass = TM_MAXCLASS;
			pmmsg.pm_type = PM_STATUS;
			switch (sacmsg.sc_type) {
			case SC_STATUS:
				break;
			case SC_ENABLE:
				log("Got SC_ENABLE message");
				oldState = State;
				State = PM_ENABLED;
				if (State != oldState) {
#ifdef	DEBUG
					debug("state changed to ENABLED");
#endif
					state_change();
				}
				break;
			case SC_DISABLE:
				log("Got SC_DISABLE message");
				oldState = State;
				State = PM_DISABLED;
				if (State != oldState) {
#ifdef	DEBUG
					debug("state changed to DISABLED");
#endif
					state_change();
				}
				break;
			case SC_READDB:
				log("Got SC_READDB message");
				Reread_flag = 1;
				break;
			default:
				log("Got unknown message %d", sacmsg.sc_type);
				pmmsg.pm_type = PM_UNKNOWN;
				break;
			} /* end switch */
			pmmsg.pm_state = State;

			while (write(Sfd, &pmmsg, sizeof (pmmsg)) !=
			    sizeof (pmmsg)) {
				if (errno == EINTR)
					continue;
				log("sanity response to SAC failed: %s",
				    strerror(errno));
				break;
			}
		}
	} /* end for loop */
}
