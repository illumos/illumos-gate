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

static	int	start(char *);
static	int	lwpstart(int *, const lwpstatus_t *, const lwpsinfo_t *);

static	char	*command;
static	const char *lwps;
static	struct	ps_prochandle *P;

int
main(int argc, char **argv)
{
	int	rc = 0;

	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	if (argc <= 1) {
		(void) fprintf(stderr, "usage:\t%s pid[/lwps] ...\n", command);
		(void) fprintf(stderr, "  (set stopped processes or lwps "
		    "running)\n");
		return (2);
	}

	while (--argc > 0)
		rc += start(*++argv);

	return (rc);
}

static int
start(char *arg)
{
	int gcode;
	int rc = 0;

	if ((P = proc_arg_xgrab(arg, NULL, PR_ARG_PIDS, PGRAB_FORCE |
	    PGRAB_RETAIN | PGRAB_NOSTOP, &gcode, &lwps)) == NULL) {
		(void) fprintf(stderr, "%s: cannot control %s: %s\n",
		    command, arg, Pgrab_error(gcode));
		return (1);
	}

	/*
	 * If the victim is stopped because of a job control signal, we
	 * need to send it SIGCONT to get it moving again, otherwise
	 * the agent will not be able to run, and so will not be able to
	 * exit the process.
	 */
	(void) kill(Pstatus(P)->pr_pid, SIGCONT);

	/*
	 * if the agent already exists, Pcreate_agent will adopt the
	 * extant agent so that we can destroy it
	 */
	if (Pstatus(P)->pr_lwp.pr_flags & PR_AGENT) {
		if (Pcreate_agent(P) != 0) {
			(void) fprintf(stderr,
			    "%s: cannot remove agent from %s: %s\n",
			    command, arg, strerror(errno));

			Prelease(P, 0);
			return (1);
		}

		Pdestroy_agent(P);
	}

	if (lwps != NULL) {
		/*
		 * The user provided an lwp specification. Let's consider the
		 * lwp specification as a mask.  We iterate over all lwps in the
		 * process and set running every lwp, which matches the mask.
		 * If there is no lwp matching the mask or an error occured
		 * during the iteration, set the return code to 1 as indication
		 * of an error.  We need to unset run-on-last-close flag,
		 * otherwise *all* lwps could be set running after detaching
		 * from the process and not only lwps, which were selected.
		 */
		int lwpcount = 0;

		(void) Punsetflags(P, PR_RLC);
		(void) Plwp_iter_all(P, (proc_lwp_all_f *)lwpstart, &lwpcount);

		if (lwpcount == 0) {
			(void) fprintf(stderr, "%s: cannot control %s:"
			    " no matching LWPs found\n", command, arg);
			rc = 1;
		} else if (lwpcount == -1)
			rc = 1;
	} else {
		(void) Psetrun(P, 0, 0);	/* Set the process running. */
	}

	/*
	 * Prelease could change the tracing flags or leave the victim hung
	 * so we free the handle by hand.
	 */
	Pfree(P);
	return (rc);
}

/* ARGSUSED */
static int
lwpstart(int *lwpcount, const lwpstatus_t *status, const lwpsinfo_t *info)
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
			(void) Lsetrun(L, 0, 0);
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
