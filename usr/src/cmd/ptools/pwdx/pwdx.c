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
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <libproc.h>
#include <sys/param.h>

#include "ptools_common.h"

static char *command;

static int
show_cwd(const char *arg)
{
	char cwd[MAXPATHLEN], proc[128];
	psinfo_t p;
	int gcode;
	int ret;

	if (proc_arg_psinfo(arg, PR_ARG_PIDS, &p, &gcode) == -1) {
		(void) fprintf(stderr, "%s: cannot examine %s: %s\n",
		    command, arg, Pgrab_error(gcode));
		return (1);
	}

	(void) proc_snprintf(proc, sizeof (proc), "/proc/%d/path/cwd",
	    (int)p.pr_pid);

	if ((ret = readlink(proc, cwd, sizeof (cwd) - 1)) <= 0) {
		(void) fprintf(stderr, "%s: cannot resolve cwd for %s: %s\n",
		    command, arg, strerror(errno));
		return (1);
	}

	cwd[ret] = '\0';

	(void) printf("%d:\t%s\n", (int)p.pr_pid, cwd);
	return (0);
}

int
main(int argc, char **argv)
{
	int retc = 0;

	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	if (argc <= 1) {
		(void) fprintf(stderr, "usage:\t%s pid ...\n", command);
		(void) fprintf(stderr, "  (show process working directory)\n");
	}

	while (--argc >= 1)
		retc += show_cwd(*++argv);

	return (retc);
}
