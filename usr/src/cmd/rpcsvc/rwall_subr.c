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
 *
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
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

/*
 * rwall_subr.c
 *	The server procedure for rwalld
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <rpc/rpc.h>
#include <thread.h>
#include <rpcsvc/rwall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <string.h>

#define	WALL_PROG	"/usr/sbin/wall"

static mutex_t wall_mutex = DEFAULTMUTEX;
static char *oldmsg;

/* ARGSUSED */
bool_t
wallproc_wall_1_svc(wrapstring *argp, void *res, struct svc_req *rqstp)
{
	char *msg;
	FILE *fp;
	int rval;
	struct stat wall;

	msg = *argp;

	/*
	 * Do not wall the same message twice in case of a retransmission
	 * in the rare case that two walls arrive close enough with
	 * a retransmission we might get a duplicate, but that is OK.
	 */
	(void) mutex_lock(&wall_mutex);
	if ((oldmsg != 0) && (strcmp(msg, oldmsg) == 0)) {
		(void) mutex_unlock(&wall_mutex);
		return (TRUE);
	}

	if (oldmsg)
		free(oldmsg);
	oldmsg = strdup(msg);

	rval = stat(WALL_PROG, &wall);

	/*
	 * Make sure the wall programs exists, is executeable, and runs
	 */
	if (rval == -1 || (wall.st_mode & S_IXUSR) == 0 ||
	    (fp = popen(WALL_PROG, "w")) == NULL) {
		syslog(LOG_NOTICE,
			"rwall message received but could not execute %s",
			WALL_PROG);
		syslog(LOG_NOTICE, "%s", msg);
#ifdef	DEBUG
		(void) fprintf(stderr,
			"rwall message received but could not execute %s",
			WALL_PROG);
		(void) fprintf(stderr, "%s", msg);
#endif
		(void) mutex_unlock(&wall_mutex);
		return (TRUE);
	}

	(void) fprintf(fp, "%s", msg);
	(void) pclose(fp);
	(void) mutex_unlock(&wall_mutex);

	return (TRUE);
}

/* ARGSUSED */
int
wallprog_1_freeresult(SVCXPRT *transp, xdrproc_t proc, caddr_t arg)
{
	return (TRUE);
}
