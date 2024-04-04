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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <libintl.h>
#include <locale.h>
#include <errno.h>
#include <kstat.h>
#include <libcpc.h>

#include "cpucmds.h"

static struct options {
	int debug;
	int verbose;
	int dotitle;
	int dohelp;
	int dotick;
	int cpuver;
	char *pgmname;
	uint_t mseconds;
	uint_t nsamples;
	uint_t nsets;
	cpc_setgrp_t *master;
	int followfork;
	int followexec;
	pid_t pid;
	FILE *log;
} __options;

static const struct options *opts = (const struct options *)&__options;

static cpc_t *cpc;

/*
 * How many signals caught from terminal
 * We bail out as soon as possible when interrupt is set
 */
static int	interrupt = 0;

/*ARGSUSED*/
static void
cputrack_errfn(const char *fn, int subcode, const char *fmt, va_list ap)
{
	(void) fprintf(stderr, "%s: ", opts->pgmname);
	if (opts->debug)
		(void) fprintf(stderr, "%s: ", fn);
	(void) vfprintf(stderr, fmt, ap);
}

static void
cputrack_pctx_errfn(const char *fn, const char *fmt, va_list ap)
{
	cputrack_errfn(fn, -1, fmt, ap);
}

static int cputrack(int argc, char *argv[], int optind);
static void intr(int);

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

int
main(int argc, char *argv[])
{
	struct options *opts = &__options;
	int c, errcnt = 0;
	int nsamples;
	cpc_setgrp_t *sgrp;
	char *errstr;
	int ret;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if ((opts->pgmname = strrchr(argv[0], '/')) == NULL)
		opts->pgmname = argv[0];
	else
		opts->pgmname++;

	if ((cpc = cpc_open(CPC_VER_CURRENT)) == NULL) {
		errstr = strerror(errno);
		(void) fprintf(stderr, gettext("%s: cannot access performance "
		    "counter library - %s\n"), opts->pgmname, errstr);
		return (1);
	}

	(void) cpc_seterrhndlr(cpc, cputrack_errfn);
	strtoset_errfn = cputrack_errfn;

	/*
	 * Establish (non-zero) defaults
	 */
	opts->mseconds = 1000;
	opts->dotitle = 1;
	opts->log = stdout;
	if ((opts->master = cpc_setgrp_new(cpc, 0)) == NULL) {
		(void) fprintf(stderr, gettext("%s: no memory available\n"),
		    opts->pgmname);
		exit(1);
	}

	while ((c = getopt(argc, argv, "T:N:Defhntvo:r:c:p:")) != EOF)
		switch (c) {
		case 'T':			/* sample time,	seconds */
			opts->mseconds = (uint_t)(atof(optarg) * 1000.0);
			break;
		case 'N':			/* number of samples */
			nsamples = atoi(optarg);
			if (nsamples < 0)
				errcnt++;
			else
				opts->nsamples = (uint_t)nsamples;
			break;
		case 'D':			/* enable debugging */
			opts->debug++;
			break;
		case 'f':			/* follow fork */
			opts->followfork++;
			break;
		case 'e':			/* follow exec */
			opts->followexec++;
			break;
		case 'n':			/* no titles */
			opts->dotitle = 0;
			break;
		case 't':			/* print %tick */
			opts->dotick = 1;
			break;
		case 'v':
			opts->verbose = 1;	/* more chatty */
			break;
		case 'o':
			if (optarg == NULL) {
				errcnt++;
				break;
			}
			if ((opts->log = fopen(optarg, "w")) == NULL) {
				(void) fprintf(stderr, gettext(
				    "%s: cannot open '%s' for writing\n"),
				    opts->pgmname, optarg);
				return (1);
			}
			break;
		case 'c':			/* specify statistics */
			if ((sgrp = cpc_setgrp_newset(opts->master,
			    optarg, &errcnt)) != NULL)
				opts->master = sgrp;
			break;
		case 'p':			/* grab given pid */
			if ((opts->pid = atoi(optarg)) <= 0)
				errcnt++;
			break;
		case 'h':
			opts->dohelp = 1;
			break;
		case '?':
		default:
			errcnt++;
			break;
		}

	if (opts->nsamples == 0)
		opts->nsamples = UINT_MAX;

	if (errcnt != 0 ||
	    opts->dohelp ||
	    (argc == optind && opts->pid == 0) ||
	    (argc > optind && opts->pid != 0) ||
	    (opts->nsets = cpc_setgrp_numsets(opts->master)) == 0) {
		(void) fprintf(opts->dohelp ? stdout : stderr, gettext(
		    "Usage:\n\t%s [-T secs] [-N count] [-Defhnv] [-o file]\n"
		    "\t\t-c events [command [args] | -p pid]\n\n"
		    "\t-T secs\t  seconds between samples, default 1\n"
		    "\t-N count  number of samples, default unlimited\n"
		    "\t-D\t  enable debug mode\n"
		    "\t-e\t  follow exec(2), and execve(2)\n"
		    "\t-f\t  follow fork(2), fork1(2), and vfork(2)\n"
		    "\t-h\t  print extended usage information\n"
		    "\t-n\t  suppress titles\n"
		    "\t-t\t  include virtualized %s register\n"
		    "\t-v\t  verbose mode\n"
		    "\t-o file\t  write cpu statistics to this file\n"
		    "\t-c events specify processor events to be monitored\n"
		    "\t-p pid\t  pid of existing process to capture\n\n"
		    "\tUse cpustat(8) to monitor system-wide statistics.\n"),
		    opts->pgmname, CPC_TICKREG_NAME);
		if (opts->dohelp) {
			(void) putchar('\n');
			(void) capabilities(cpc, stdout);
			exit(0);
		}
		exit(2);
	}

	/*
	 * Catch signals from terminal, so they can be handled asynchronously
	 * when we're ready instead of when we're not (;-)
	 */
	if (sigset(SIGHUP, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGHUP, intr);
	if (sigset(SIGINT, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGINT, intr);
	if (sigset(SIGQUIT, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGQUIT, intr);
	(void) sigset(SIGPIPE, intr);
	(void) sigset(SIGTERM, intr);

	cpc_setgrp_reset(opts->master);
	(void) setvbuf(opts->log, NULL, _IOLBF, 0);
	ret = cputrack(argc, argv, optind);
	(void) cpc_close(cpc);
	return (ret);
}

static void
print_title(cpc_setgrp_t *sgrp)
{
	(void) fprintf(opts->log, "%7s ", "time");
	if (opts->followfork)
		(void) fprintf(opts->log, "%6s ", "pid");
	(void) fprintf(opts->log, "%3s %10s ", "lwp", "event");
	if (opts->dotick)
		(void) fprintf(opts->log, "%9s ", CPC_TICKREG_NAME);
	(void) fprintf(opts->log, "%s\n", cpc_setgrp_gethdr(sgrp));
	(void) fflush(opts->log);
}

static void
print_exec(float now, pid_t pid, char *name)
{
	if (name == NULL)
		name = "(unknown)";

	(void) fprintf(opts->log, "%7.3f ", now);
	if (opts->followfork)
		(void) fprintf(opts->log, "%6d ", (int)pid);
	(void) fprintf(opts->log, "%3d %10s ", 1, "exec");
	if (opts->dotick)
		(void) fprintf(opts->log, "%9s ", "");
	(void) fprintf(opts->log, "%9s %9s # '%s'\n", "", "", name);
	(void) fflush(opts->log);
}

static void
print_fork(float now, pid_t newpid, id_t lwpid, pid_t oldpid)
{
	(void) fprintf(opts->log, "%7.3f ", now);
	if (opts->followfork)
		(void) fprintf(opts->log, "%6d ", (int)oldpid);
	(void) fprintf(opts->log, "%3d %10s ", (int)lwpid, "fork");
	if (opts->dotick)
		(void) fprintf(opts->log, "%9s ", "");
	(void) fprintf(opts->log, "%9s %9s # %d\n", "", "", (int)newpid);
	(void) fflush(opts->log);
}

static void
print_sample(pid_t pid, id_t lwpid,
    char *pevent, cpc_buf_t *buf, int nreq, const char *evname)
{
	uint64_t	val;
	int		i;

	(void) fprintf(opts->log, "%7.3f ",
	    mstimestamp(cpc_buf_hrtime(cpc, buf)));
	if (opts->followfork)
		(void) fprintf(opts->log, "%6d ", (int)pid);
	(void) fprintf(opts->log, "%3d %10s ", (int)lwpid, pevent);
	if (opts->dotick)
		(void) fprintf(opts->log, "%9" PRId64 " ",
		    cpc_buf_tick(cpc, buf));
	for (i = 0; i < nreq; i++) {
		(void) cpc_buf_get(cpc, buf, i, &val);
		(void) fprintf(opts->log, "%9" PRId64 " ", val);
	}
	if (opts->nsets > 1)
		(void) fprintf(opts->log, " # %s\n", evname);
	else
		(void) fputc('\n', opts->log);
}

struct pstate {
	cpc_setgrp_t *accum;
	cpc_setgrp_t **sgrps;
	int maxlwpid;
};

static int
pinit_lwp(pctx_t *pctx, pid_t pid, id_t lwpid, void *arg)
{
	struct pstate *state = arg;
	cpc_setgrp_t *sgrp;
	cpc_set_t *set;
	cpc_buf_t **data1, **data2, **scratch;
	char *errstr;
	int nreq;

	if (interrupt)
		return (0);

	if (state->maxlwpid < lwpid) {
		state->sgrps = realloc(state->sgrps,
		    lwpid * sizeof (state->sgrps));
		if (state->sgrps == NULL) {
			(void) fprintf(stderr, gettext(
			    "%6d: init_lwp: out of memory\n"), (int)pid);
			return (-1);
		}
		while (state->maxlwpid < lwpid) {
			state->sgrps[state->maxlwpid] = NULL;
			state->maxlwpid++;
		}
	}

	if ((sgrp = state->sgrps[lwpid-1]) == NULL) {
		if ((sgrp = cpc_setgrp_clone(opts->master)) == NULL) {
			(void) fprintf(stderr, gettext(
			    "%6d: init_lwp: out of memory\n"), (int)pid);
			return (-1);
		}
		state->sgrps[lwpid-1] = sgrp;
		set = cpc_setgrp_getset(sgrp);
	} else {
		cpc_setgrp_reset(sgrp);
		set = cpc_setgrp_getset(sgrp);
	}

	nreq = cpc_setgrp_getbufs(sgrp, &data1, &data2, &scratch);

	if (cpc_bind_pctx(cpc, pctx, lwpid, set, 0) != 0 ||
	    cpc_set_sample(cpc, set, *data2) != 0) {
		errstr = strerror(errno);
		if (errno == EAGAIN) {
			(void) cpc_unbind(cpc, set);
		}

		(void) fprintf(stderr, gettext(
		    "%6d: init_lwp: can't bind perf counters "
		    "to lwp%d - %s\n"), (int)pid, (int)lwpid, errstr);
		return (-1);
	}

	if (opts->verbose)
		print_sample(pid, lwpid, "init_lwp",
		    *data2, nreq, cpc_setgrp_getname(sgrp));
	return (0);
}

/*ARGSUSED*/
static int
pfini_lwp(pctx_t *pctx, pid_t pid, id_t lwpid, void *arg)
{
	struct pstate *state = arg;
	cpc_setgrp_t *sgrp = state->sgrps[lwpid-1];
	cpc_set_t *set;
	char *errstr;
	cpc_buf_t **data1, **data2, **scratch;
	int nreq;

	if (interrupt)
		return (0);

	set = cpc_setgrp_getset(sgrp);
	nreq = cpc_setgrp_getbufs(sgrp, &data1, &data2, &scratch);
	if (cpc_set_sample(cpc, set, *scratch) == 0) {
		if (opts->nsets == 1) {
			/*
			 * When we only have one set of counts, the sample
			 * gives us the accumulated count.
			 */
			*data1 = *scratch;
		} else {
			/*
			 * When we have more than one set of counts, the
			 * sample gives us the count for the latest sample
			 * period. *data1 contains the accumulated count but
			 * does not include the count for the latest sample
			 * period for this set of counters.
			 */
			cpc_buf_add(cpc, *data1, *data1, *scratch);
		}
		if (opts->verbose)
			print_sample(pid, lwpid, "fini_lwp",
			    *data1, nreq, cpc_setgrp_getname(sgrp));
		cpc_setgrp_accum(state->accum, sgrp);
		if (cpc_unbind(cpc, set) == 0)
			return (0);
	}

	switch (errno) {
	case EAGAIN:
		(void) fprintf(stderr, gettext("%6d: fini_lwp: "
		    "lwp%d: perf counter contents invalidated\n"),
		    (int)pid, (int)lwpid);
		break;
	default:
		errstr = strerror(errno);
		(void) fprintf(stderr, gettext("%6d: fini_lwp: "
		    "lwp%d: can't access perf counters - %s\n"),
		    (int)pid, (int)lwpid, errstr);
		break;
	}
	return (-1);
}

/*ARGSUSED*/
static int
plwp_create(pctx_t *pctx, pid_t pid, id_t lwpid, void *arg)
{
	cpc_setgrp_t	*sgrp = opts->master;
	cpc_buf_t	**data1, **data2, **scratch;
	int		nreq;

	if (interrupt)
		return (0);

	nreq = cpc_setgrp_getbufs(sgrp, &data1, &data2, &scratch);

	print_sample(pid, lwpid, "lwp_create",
	    *data1, nreq, cpc_setgrp_getname(sgrp));

	return (0);
}

/*ARGSUSED*/
static int
plwp_exit(pctx_t *pctx, pid_t pid, id_t lwpid, void *arg)
{
	struct pstate	*state = arg;
	cpc_setgrp_t	*sgrp = state->sgrps[lwpid-1];
	cpc_set_t	*start;
	int		nreq;
	cpc_buf_t	**data1, **data2, **scratch;

	if (interrupt)
		return (0);

	start = cpc_setgrp_getset(sgrp);
	do {
		nreq = cpc_setgrp_getbufs(sgrp, &data1, &data2, &scratch);
		if (cpc_buf_hrtime(cpc, *data1) == 0)
			continue;
		print_sample(pid, lwpid, "lwp_exit",
		    *data1, nreq, cpc_setgrp_getname(sgrp));
	} while (cpc_setgrp_nextset(sgrp) != start);

	return (0);
}

/*ARGSUSED*/
static int
pexec(pctx_t *pctx, pid_t pid, id_t lwpid, char *name, void *arg)
{
	struct pstate	*state = arg;
	float		now = 0.0;
	cpc_set_t	*start;
	int		nreq;
	cpc_buf_t	**data1, **data2, **scratch;
	hrtime_t	hrt;

	if (interrupt)
		return (0);

	/*
	 * Print the accumulated results from the previous program image
	 */
	cpc_setgrp_reset(state->accum);
	start = cpc_setgrp_getset(state->accum);
	do {
		nreq = cpc_setgrp_getbufs(state->accum, &data1, &data2,
		    &scratch);
		hrt = cpc_buf_hrtime(cpc, *data1);
		if (hrt == 0)
			continue;
		print_sample(pid, lwpid, "exec",
		    *data1, nreq, cpc_setgrp_getname(state->accum));
		if (now < mstimestamp(hrt))
			now = mstimestamp(hrt);
	} while (cpc_setgrp_nextset(state->accum) != start);

	print_exec(now, pid, name);

	if (state->accum != NULL) {
		cpc_setgrp_free(state->accum);
		state->accum = NULL;
	}

	if (opts->followexec) {
		state->accum = cpc_setgrp_clone(opts->master);
		return (0);
	}
	return (-1);
}

/*ARGSUSED*/
static void
pexit(pctx_t *pctx, pid_t pid, id_t lwpid, int status, void *arg)
{
	struct pstate	*state = arg;
	cpc_set_t	*start;
	int		nreq;
	cpc_buf_t	**data1, **data2, **scratch;

	if (interrupt)
		return;

	cpc_setgrp_reset(state->accum);
	start = cpc_setgrp_getset(state->accum);
	do {
		nreq = cpc_setgrp_getbufs(state->accum, &data1, &data2,
		    &scratch);
		if (cpc_buf_hrtime(cpc, *data1) == 0)
			continue;
		print_sample(pid, lwpid, "exit",
		    *data1, nreq, cpc_setgrp_getname(state->accum));
	} while (cpc_setgrp_nextset(state->accum) != start);

	cpc_setgrp_free(state->accum);
	state->accum = NULL;

	for (lwpid = 1; lwpid < state->maxlwpid; lwpid++)
		if (state->sgrps[lwpid-1] != NULL) {
			cpc_setgrp_free(state->sgrps[lwpid-1]);
			state->sgrps[lwpid-1] = NULL;
		}
	free(state->sgrps);
	state->sgrps = NULL;
}

static int
ptick(pctx_t *pctx, pid_t pid, id_t lwpid, void *arg)
{
	struct pstate *state = arg;
	cpc_setgrp_t *sgrp = state->sgrps[lwpid-1];
	cpc_set_t *this = cpc_setgrp_getset(sgrp);
	const char *name = cpc_setgrp_getname(sgrp);
	cpc_buf_t **data1, **data2, **scratch, *tmp;
	char *errstr;
	int nreqs;

	if (interrupt)
		return (0);

	nreqs = cpc_setgrp_getbufs(sgrp, &data1, &data2, &scratch);

	if (opts->nsets == 1) {
		/*
		 * If we're dealing with one set, buffer usage is:
		 *
		 * data1 = most recent data snapshot
		 * data2 = previous data snapshot
		 * scratch = used for diffing data1 and data2
		 *
		 * Save the snapshot from the previous sample in data2
		 * before putting the current sample in data1.
		 */
		tmp = *data1;
		*data1 = *data2;
		*data2 = tmp;
		if (cpc_set_sample(cpc, this, *data1) != 0)
			goto broken;
		cpc_buf_sub(cpc, *scratch, *data1, *data2);
	} else {
		cpc_set_t *next = cpc_setgrp_nextset(sgrp);
		/*
		 * If there is more than set in use, we will need to
		 * unbind and re-bind on each go-around because each
		 * time a counter is bound, it is preset to 0 (as it was
		 * specified when the requests were added to the set).
		 *
		 * Buffer usage in this case is:
		 *
		 * data1 = total counts for this set since program began
		 * data2 = unused
		 * scratch = most recent data snapshot
		 */

		if (cpc_set_sample(cpc, this, *scratch) != 0)
			goto broken;
		cpc_buf_add(cpc, *data1, *data1, *scratch);

		/*
		 * No need to unbind the previous set, as binding another set
		 * automatically unbinds the most recently bound set.
		 */
		if (cpc_bind_pctx(cpc, pctx, lwpid, next, 0) != 0)
			goto broken;
	}
	print_sample(pid, lwpid, "tick", *scratch, nreqs, name);

	return (0);

broken:
	switch (errno) {
	case EAGAIN:
		(void) fprintf(stderr, gettext(
		    "%6d: tick: lwp%d: perf counter contents invalidated\n"),
		    (int)pid, (int)lwpid);
		break;
	default:
		errstr = strerror(errno);
		(void) fprintf(stderr, gettext(
		    "%6d: tick: lwp%d: can't access perf counter - %s\n"),
		    (int)pid, (int)lwpid, errstr);
		break;
	}
	(void) cpc_unbind(cpc, this);
	return (-1);
}

/*
 * The system has just created a new address space that has a new pid.
 * We're running in a child of the controlling process, with a new
 * pctx handle already opened on the child of the original controlled process.
 */
static void
pfork(pctx_t *pctx, pid_t oldpid, pid_t pid, id_t lwpid, void *arg)
{
	struct pstate *state = arg;

	print_fork(mstimestamp(0), pid, lwpid, oldpid);

	if (!opts->followfork)
		return;

	if (pctx_set_events(pctx,
	    PCTX_SYSC_EXEC_EVENT, pexec,
	    PCTX_SYSC_FORK_EVENT, pfork,
	    PCTX_SYSC_EXIT_EVENT, pexit,
	    PCTX_SYSC_LWP_CREATE_EVENT, plwp_create,
	    PCTX_INIT_LWP_EVENT, pinit_lwp,
	    PCTX_FINI_LWP_EVENT, pfini_lwp,
	    PCTX_SYSC_LWP_EXIT_EVENT, plwp_exit,
	    PCTX_NULL_EVENT) == 0) {
		state->accum = cpc_setgrp_clone(opts->master);
		(void) pctx_run(pctx, opts->mseconds, opts->nsamples, ptick);
		if (state->accum) {
			free(state->accum);
			state->accum = NULL;
		}
	}
}

/*
 * Translate the incoming options into actions, and get the
 * tool and the process to control running.
 */
static int
cputrack(int argc, char *argv[], int optind)
{
	struct pstate __state, *state = &__state;
	pctx_t *pctx;
	int err;

	bzero(state, sizeof (*state));

	if (opts->pid == 0) {
		if (argc <= optind) {
			(void) fprintf(stderr, "%s: %s\n",
			    opts->pgmname,
			    gettext("no program to start"));
			return (1);
		}
		pctx = pctx_create(argv[optind],
		    &argv[optind], state, 1, cputrack_pctx_errfn);
		if (pctx == NULL) {
			(void) fprintf(stderr, "%s: %s '%s'\n",
			    opts->pgmname,
			    gettext("failed to start program"),
			    argv[optind]);
			return (1);
		}
	} else {
		pctx = pctx_capture(opts->pid, state, 1, cputrack_pctx_errfn);
		if (pctx == NULL) {
			(void) fprintf(stderr, "%s: %s %d\n",
			    opts->pgmname,
			    gettext("failed to capture pid"),
			    (int)opts->pid);
			return (1);
		}
	}

	err = pctx_set_events(pctx,
	    PCTX_SYSC_EXEC_EVENT, pexec,
	    PCTX_SYSC_FORK_EVENT, pfork,
	    PCTX_SYSC_EXIT_EVENT, pexit,
	    PCTX_SYSC_LWP_CREATE_EVENT, plwp_create,
	    PCTX_INIT_LWP_EVENT, pinit_lwp,
	    PCTX_FINI_LWP_EVENT, pfini_lwp,
	    PCTX_SYSC_LWP_EXIT_EVENT, plwp_exit,
	    PCTX_NULL_EVENT);

	if (err != 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    opts->pgmname,
		    gettext("can't bind process context ops to process"));
	} else {
		if (opts->dotitle)
			print_title(opts->master);
		state->accum = cpc_setgrp_clone(opts->master);
		zerotime();
		err = pctx_run(pctx, opts->mseconds, opts->nsamples, ptick);
		if (state->accum) {
			cpc_setgrp_free(state->accum);
			state->accum = NULL;
		}
	}

	return (err != 0 ? 1 : 0);
}

/*ARGSUSED*/
static void
intr(int sig)
{
	interrupt++;
	if (cpc != NULL)
		cpc_terminate(cpc);
}
