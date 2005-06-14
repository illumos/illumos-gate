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
 * Copyright (c) 1994-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>
#include <libproc.h>

static	int	stop(char *);
static	int	perr(char *);

static	char	*command;
static	char	*procname;

int
main(int argc, char **argv)
{
	int rc = 0;

	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	if (argc <= 1) {
		(void) fprintf(stderr, "usage:\t%s pid ...\n", command);
		(void) fprintf(stderr,
			"  (stop processes with /proc request)\n");
		return (2);
	}

	while (--argc > 0)
		rc += stop(*++argv);

	return (rc);
}

static int
stop(char *arg)
{
	char ctlfile[100];
	long ctl[1];
	int ctlfd, gcode;
	pid_t pid;

	procname = arg;		/* for perr() */
	if ((pid = proc_arg_psinfo(arg, PR_ARG_PIDS, NULL, &gcode)) == -1) {
		(void) fprintf(stderr, "%s: cannot control %s: %s\n",
			command, arg, Pgrab_error(gcode));
		return (1);
	}

	(void) sprintf(ctlfile, "/proc/%d/ctl", (int)pid);
	errno = 0;
	if ((ctlfd = open(ctlfile, O_WRONLY)) >= 0) {
		ctl[0] = PCDSTOP;
		(void) write(ctlfd, ctl, sizeof (long));
		(void) close(ctlfd);
	}

	return (perr(NULL));
}

static int
perr(char *s)
{
	if (errno == 0)
		return (0);
	if (s)
		(void) fprintf(stderr, "%s: ", procname);
	else
		s = procname;
	perror(s);
	return (1);
}
