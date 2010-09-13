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
static	int	lwpstop(int *, const lwpstatus_t *, const lwpsinfo_t *);

static	char	*command;
static	const char *lwps;
static	struct	ps_prochandle *P;

int
main(int argc, char **argv)
{
	int rc = 0;

	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	if (argc <= 1) {
		(void) fprintf(stderr, "usage:\t%s pid[/lwps] ...\n", command);
		(void) fprintf(stderr,
		    "  (stop processes or lwps with /proc request)\n");
		return (2);
	}

	while (--argc > 0)
		rc += stop(*++argv);

	return (rc);
}

static int
stop(char *arg)
{
	int gcode;
	int rc = 0;

	if ((P = proc_arg_xgrab(arg, NULL, PR_ARG_PIDS, PGRAB_RETAIN |
	    PGRAB_NOSTOP | PGRAB_FORCE, &gcode, &lwps)) == NULL) {
		(void) fprintf(stderr, "%s: cannot control %s: %s\n",
		    command, arg, Pgrab_error(gcode));
		return (1);
	} else if (lwps != NULL) {
		/*
		 * The user has provided an lwp specification.  Let's consider
		 * the lwp specification as a mask.  We iterate over all lwps in
		 * the process and stop every lwp, which matches the mask.  If
		 * there is no lwp matching the mask or an error occured during
		 * the iteration, set the return code to 1 as indication of an
		 * error.
		 */
		int lwpcount = 0;

		(void) Plwp_iter_all(P, (proc_lwp_all_f *)lwpstop, &lwpcount);
		if (lwpcount == 0) {
			(void) fprintf(stderr, "%s: cannot control %s:"
			    " no matching LWPs found\n", command, arg);
			rc = 1;
		} else if (lwpcount == -1)
			rc = 1;
	} else {
		(void) Pdstop(P);	/* Stop the process. */
	}

	/*
	 * Prelease could change the tracing flags, use Pfree and unset
	 * run-on-last-close flag to prevent the process being set running
	 * after detaching from it.
	 */
	(void) Punsetflags(P, PR_RLC);
	Pfree(P);
	return (rc);
}

/* ARGSUSED */
static int
lwpstop(int *lwpcount, const lwpstatus_t *status, const lwpsinfo_t *info)
{
	struct ps_lwphandle *L;
	int gcode;

	if (proc_lwp_in_set(lwps, info->pr_lwpid)) {
		/*
		 * There is a race between the callback from the iterator and
		 * grabbing of the lwp.  If the lwp has already exited, Lgrab
		 * will return the error code G_NOPROC.  It's not a real error,
		 * only if there is no lwp matching the specification.
		 */
		if ((L = Lgrab(P, info->pr_lwpid, &gcode)) != NULL) {
			(void) Ldstop(L);
			Lfree(L);
			if (*lwpcount >= 0)
				(*lwpcount)++;
		} else if (gcode != G_NOPROC) {
			(void) fprintf(stderr, "%s: cannot control %d/%d: %s\n",
			    command, (int)Pstatus(P)->pr_pid,
			    (int)info->pr_lwpid, Lgrab_error(gcode));
			*lwpcount = -1;
		}
	}
	return (0);
}
