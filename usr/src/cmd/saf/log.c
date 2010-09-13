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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <strings.h>
#include <errno.h>

#include "extern.h"
#include "misc.h"
#include "msgs.h"
#include <sac.h>
#include "structs.h"

static	FILE	*Lfp;	/* log file */
#ifdef DEBUG
static	FILE	*Dfp;	/* debug file */
#endif


/*
 * cons_printf - emit a message to the system console
 */

/*PRINTFLIKE1*/
static void
cons_printf(const char *fmt, ...)
{
	char buf[MAXPATHLEN * 2]; /* enough space for msg including a path */
	int fd;
	va_list ap;

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	if ((fd = open("/dev/console", O_WRONLY|O_NOCTTY)) != -1)
		(void) write(fd, buf, strlen(buf) + 1);
	(void) close(fd);
}

/*
 * openlog - open log file, sets global file pointer Lfp
 */

void
openlog()
{
	if ((Lfp = fopen(LOGFILE, "a+")) == NULL) {
		cons_printf("SAC: could not open logfile %s: %s\n",
		    LOGFILE, strerror(errno));
		exit(1);
	}

	/*
	 * lock logfile to indicate presence
	 */
	if (lockf(fileno(Lfp), F_LOCK, 0) < 0) {
		cons_printf("SAC: could not lock logfile %s:%s\n",
		    LOGFILE, strerror(errno));
		exit(1);
	}
}


/*
 * log - put a message into the log file
 *
 *	args:	msg - message to be logged
 */
void
log(char *msg)
{
	char *timestamp;	/* current time in readable form */
	time_t clock;		/* current time in seconds */
	char buf[SIZE];		/* scratch buffer */

	(void) time(&clock);
	timestamp = ctime(&clock);
	*(strchr(timestamp, '\n')) = '\0';
	(void) snprintf(buf, sizeof (buf), "%s; %ld; %s\n",
	    timestamp, getpid(), msg);
	(void) fprintf(Lfp, buf);
	(void) fflush(Lfp);
}


/*
 * error - put an error message into the log file and exit if indicated
 *
 *	args:	msgid - id of message to be output
 *		action - action to be taken (EXIT or not)
 */


void
error(int msgid, int action)
{
	if (msgid < 0 || msgid > N_msgs)
		return;
	log(Msgs[msgid].e_str);
	if (action == EXIT) {
		log("*** SAC exiting ***");
		exit(Msgs[msgid].e_exitcode);
	}
}


#ifdef DEBUG

/*
 * opendebug - open debugging file, sets global file pointer Dfp
 */


void
opendebug()
{
	FILE *fp;	/* scratch file pointer for problems */

	if ((Dfp = fopen(DBGFILE, "a+")) == NULL) {
		cons_printf("SAC: could not open debugfile %s: %s\n",
		    DBGFILE, strerror(errno));
		exit(1);
	}
}


/*
 * debug - put a message into debug file
 *
 *	args:	msg - message to be output
 */


void
debug(char *msg)
{
	char *timestamp;	/* current time in readable form */
	time_t clock;		/* current time in seconds */
	char buf[SIZE];		/* scratch buffer */

	(void) time(&clock);
	timestamp = ctime(&clock);
	*(strchr(timestamp, '\n')) = '\0';
	(void) sprintf(buf, "%s; %ld; %s\n", timestamp, getpid(), msg);
	(void) fprintf(Dfp, buf);
	(void) fflush(Dfp);
}

#endif /* DEBUG */
