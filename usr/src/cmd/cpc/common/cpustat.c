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

#include <sys/types.h>
#include <sys/processor.h>
#include <sys/pset.h>
#include <sys/lwp.h>
#include <sys/priocntl.h>
#include <sys/fxpriocntl.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <strings.h>
#include <thread.h>
#include <errno.h>
#include <libintl.h>
#include <locale.h>
#include <kstat.h>
#include <synch.h>
#include <libcpc.h>
#include <sys/resource.h>

#include "cpucmds.h"
#include "statcommon.h"

static struct options {
	int debug;
	int dotitle;
	int dohelp;
	int dotick;
	int dosoaker;
	int doperiod;
	char *pgmname;
	uint_t mseconds;
	uint_t nsamples;
	uint_t nsets;
	uint_t mseconds_rest;
	cpc_setgrp_t *master;
} __options;

/*
 * States for soaker threads.
 */
#define	SOAK_PAUSE	0
#define	SOAK_RUN	1

struct tstate {
	processorid_t	cpuid;
	int		chip_id;
	cpc_setgrp_t	*sgrp;
	int		status;
	thread_t	tid;
	int		soak_state;
	mutex_t		soak_lock;
	cond_t		soak_cv;
};

static const struct options *opts = (const struct options *)&__options;

static cpc_t *cpc;

struct tstate	*gstate;
static int	ncpus;
static int	max_chip_id;
static int	*chip_designees;    /* cpuid of CPU which counts for phs chip */
static int	smt = 0;	    /* If set, cpustat needs to be SMT-aware. */
static pcinfo_t	fxinfo = { 0, "FX", NULL }; /* FX scheduler class info */

static uint_t timestamp_fmt = NODATE;

/*ARGSUSED*/
static void
cpustat_errfn(const char *fn, int subcode, const char *fmt, va_list ap)
{
	(void) fprintf(stderr, "%s: ", opts->pgmname);
	if (opts->debug)
		(void) fprintf(stderr, "%s: ", fn);
	(void) vfprintf(stderr, fmt, ap);
}

static int cpustat(void);
static int get_chipid(kstat_ctl_t *kc, processorid_t cpuid);
static void *soaker(void *arg);


#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

int
main(int argc, char *argv[])
{
	struct options	*opts = &__options;
	int		c, errcnt = 0, ret;
	cpc_setgrp_t	*sgrp;
	char		*errstr;
	double		period;
	char		*endp;
	struct rlimit	rl;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if ((opts->pgmname = strrchr(argv[0], '/')) == NULL)
		opts->pgmname = argv[0];
	else
		opts->pgmname++;

	/* Make sure we can open enough files */
	rl.rlim_max = rl.rlim_cur = RLIM_INFINITY;
	if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
		errstr = strerror(errno);
		(void) fprintf(stderr,
		    gettext("%s: setrlimit failed - %s\n"),
		    opts->pgmname, errstr);
	}

	if ((cpc = cpc_open(CPC_VER_CURRENT)) == NULL) {
		errstr = strerror(errno);
		(void) fprintf(stderr, gettext("%s: cannot access performance "
		    "counters - %s\n"), opts->pgmname, errstr);
		return (1);
	}

	(void) cpc_seterrhndlr(cpc, cpustat_errfn);
	strtoset_errfn = cpustat_errfn;

	/*
	 * Check to see if cpustat needs to be SMT-aware.
	 */
	smt = smt_limited_cpc_hw(cpc);

	/*
	 * Establish some defaults
	 */
	opts->mseconds = 5000;
	opts->nsamples = UINT_MAX;
	opts->dotitle = 1;
	if ((opts->master = cpc_setgrp_new(cpc, smt)) == NULL) {
		(void) fprintf(stderr, gettext("%s: out of heap\n"),
		    opts->pgmname);
		return (1);
	}

	while ((c = getopt(argc, argv, "Dc:hntT:sp:")) != EOF && errcnt == 0)
		switch (c) {
		case 'D':			/* enable debugging */
			opts->debug++;
			break;
		case 'c':			/* specify statistics */
			if ((sgrp = cpc_setgrp_newset(opts->master,
			    optarg, &errcnt)) != NULL)
				opts->master = sgrp;
			break;
		case 'n':			/* no titles */
			opts->dotitle = 0;
			break;
		case 'p':			/* periodic behavior */
			opts->doperiod = 1;
			period = strtod(optarg, &endp);
			if (*endp != '\0') {
				(void) fprintf(stderr, gettext("%s: invalid "
				    "parameter \"%s\"\n"), opts->pgmname,
				    optarg);
				errcnt++;
			}
			break;
		case 's':			/* run soaker thread */
			opts->dosoaker = 1;
			break;
		case 't':			/* print %tick */
			opts->dotick = 1;
			break;
		case 'T':
			if (optarg) {
				if (*optarg == 'u')
					timestamp_fmt = UDATE;
				else if (*optarg == 'd')
					timestamp_fmt = DDATE;
				else
					errcnt++;
			} else {
				errcnt++;
			}
			break;
		case 'h':			/* help */
			opts->dohelp = 1;
			break;
		case '?':
		default:
			errcnt++;
			break;
		}

	switch (argc - optind) {
	case 0:
		break;
	case 2:
		opts->nsamples = strtol(argv[optind + 1], &endp, 10);
		if (*endp != '\0') {
			(void) fprintf(stderr,
			    gettext("%s: invalid argument \"%s\"\n"),
			    opts->pgmname, argv[optind + 1]);
			errcnt++;
			break;
		}
		/*FALLTHROUGH*/
	case 1:
		opts->mseconds = (uint_t)(strtod(argv[optind], &endp) * 1000.0);
		if (*endp != '\0') {
			(void) fprintf(stderr,
			    gettext("%s: invalid argument \"%s\"\n"),
			    opts->pgmname, argv[optind]);
			errcnt++;
		}
		break;
	default:
		errcnt++;
		break;
	}

	if (opts->nsamples == 0 || opts->mseconds == 0)
		errcnt++;

	if (errcnt != 0 || opts->dohelp ||
	    (opts->nsets = cpc_setgrp_numsets(opts->master)) == 0) {
		(void) fprintf(opts->dohelp ? stdout : stderr, gettext(
		    "Usage:\n\t%s -c spec [-c spec]... [-p period] [-T u|d]\n"
		    "\t\t[-sntD] [interval [count]]\n\n"
		    "\t-c spec\t  specify processor events to be monitored\n"
		    "\t-n\t  suppress titles\n"
		    "\t-p period cycle through event list periodically\n"
		    "\t-s\t  run user soaker thread for system-only events\n"
		    "\t-t\t  include %s register\n"
		    "\t-T d|u\t  Display a timestamp in date (d) or unix "
		    "time_t (u)\n"
		    "\t-D\t  enable debug mode\n"
		    "\t-h\t  print extended usage information\n\n"
		    "\tUse cputrack(1) to monitor per-process statistics.\n"),
		    opts->pgmname, CPC_TICKREG_NAME);
		if (opts->dohelp) {
			(void) putchar('\n');
			(void) capabilities(cpc, stdout);
			exit(0);
		}
		exit(2);
	}

	/*
	 * If the user requested periodic behavior, calculate the rest time
	 * between cycles.
	 */
	if (opts->doperiod) {
		opts->mseconds_rest = (uint_t)((period * 1000.0) -
		    (opts->mseconds * opts->nsets));
		if ((int)opts->mseconds_rest < 0)
			opts->mseconds_rest = 0;
		if (opts->nsamples != UINT_MAX)
			opts->nsamples *= opts->nsets;
	}

	cpc_setgrp_reset(opts->master);
	(void) setvbuf(stdout, NULL, _IOLBF, 0);

	/*
	 * If no system-mode only sets were created, no soaker threads will be
	 * needed.
	 */
	if (opts->dosoaker == 1 && cpc_setgrp_has_sysonly(opts->master) == 0)
		opts->dosoaker = 0;

	ret = cpustat();

	(void) cpc_close(cpc);

	return (ret);
}

static void
print_title(cpc_setgrp_t *sgrp)
{
	(void) printf("%7s %3s %5s ", "time", "cpu", "event");
	if (opts->dotick)
		(void) printf("%9s ", CPC_TICKREG_NAME);
	(void) printf("%s\n", cpc_setgrp_gethdr(sgrp));
}

static void
print_sample(processorid_t cpuid, cpc_buf_t *buf, int nreq, const char *setname,
    int sibling)
{
	char		line[1024];
	int		ccnt;
	int		i;
	uint64_t	val;
	uint64_t	tick;
	hrtime_t	hrtime;

	hrtime = cpc_buf_hrtime(cpc, buf);
	tick = cpc_buf_tick(cpc, buf);

	ccnt = snprintf(line, sizeof (line), "%7.3f %3d %5s ",
	    mstimestamp(hrtime), (int)cpuid, "tick");
	if (opts->dotick)
		ccnt += snprintf(line + ccnt, sizeof (line) - ccnt,
		    "%9" PRId64 " ", tick);
	for (i = 0; i < nreq; i++) {
		(void) cpc_buf_get(cpc, buf, i, &val);
		ccnt += snprintf(line + ccnt, sizeof (line) - ccnt,
		    "%9" PRId64 " ", val);
	}
	if (opts->nsets > 1)
		ccnt += snprintf(line + ccnt, sizeof (line) - ccnt,
		    " # %s\n", setname);
	else
		ccnt += snprintf(line + ccnt, sizeof (line) - ccnt, "\n");

	if (sibling) {
		/*
		 * This sample is being printed for a "sibling" CPU -- that is,
		 * a CPU which does not have its own CPC set bound. It is being
		 * measured via a set bound to another CPU sharing its physical
		 * processor.
		 */
		int designee = chip_designees[gstate[cpuid].chip_id];
		char *p;

		if ((p = strrchr(line, '#')) == NULL)
			p = strrchr(line, '\n');

		if (p != NULL) {
			*p = '\0';
			ccnt = strlen(line);
			ccnt += snprintf(line + ccnt, sizeof (line) - ccnt,
			    "# counter shared with CPU %d\n", designee);
		}
	}

	if (timestamp_fmt != NODATE)
		print_timestamp(timestamp_fmt);
	if (ccnt > sizeof (line))
		ccnt = sizeof (line);
	if (ccnt > 0)
		(void) write(1, line, ccnt);

	/*
	 * If this CPU is the chip designee for any other CPUs, print a line for
	 * them here.
	 */
	if (smt && (sibling == 0)) {
		for (i = 0; i < ncpus; i++) {
			if ((i != cpuid) && (gstate[i].cpuid != -1) &&
			    (chip_designees[gstate[i].chip_id] == cpuid))
				print_sample(i, buf, nreq, setname, 1);
		}
	}
}

static void
print_total(int ncpus, cpc_buf_t *buf, int nreq, const char *setname)
{
	int		i;
	uint64_t	val;

	(void) printf("%7.3f %3d %5s ", mstimestamp(cpc_buf_hrtime(cpc, buf)),
	    ncpus, "total");
	if (opts->dotick)
		(void) printf("%9" PRId64 " ", cpc_buf_tick(cpc, buf));
	for (i = 0; i < nreq; i++) {
		(void) cpc_buf_get(cpc, buf, i, &val);
		(void) printf("%9" PRId64 " ", val);
	}
	if (opts->nsets > 1)
		(void) printf(" # %s", setname);
	(void) fputc('\n', stdout);
}

#define	NSECS_PER_MSEC	1000000ll
#define	NSECS_PER_SEC	1000000000ll

static void *
gtick(void *arg)
{
	struct tstate		*state = arg;
	char			*errstr;
	uint_t			nsamples;
	uint_t			sample_cnt = 1;
	hrtime_t		ht, htdelta, restdelta;
	cpc_setgrp_t		*sgrp = state->sgrp;
	cpc_set_t		*this = cpc_setgrp_getset(sgrp);
	const char		*name = cpc_setgrp_getname(sgrp);
	cpc_buf_t		**data1, **data2, **scratch;
	cpc_buf_t		*tmp;
	int			nreqs;
	thread_t		tid;

	htdelta = NSECS_PER_MSEC * opts->mseconds;
	restdelta = NSECS_PER_MSEC * opts->mseconds_rest;
	ht = gethrtime();

	/*
	 * If this CPU is SMT, we run one gtick() thread per _physical_ CPU,
	 * instead of per cpu_t. The following check returns if it detects that
	 * this cpu_t has not been designated to do the counting for this
	 * physical CPU.
	 */
	if (smt && chip_designees[state->chip_id] != state->cpuid)
		return (NULL);

	/*
	 * If we need to run a soaker thread on this CPU, start it here.
	 */
	if (opts->dosoaker) {
		if (cond_init(&state->soak_cv, USYNC_THREAD, NULL) != 0)
			goto bad;
		if (mutex_init(&state->soak_lock, USYNC_THREAD,
		    NULL) != 0)
			goto bad;
		(void) mutex_lock(&state->soak_lock);
		state->soak_state = SOAK_PAUSE;
		if (thr_create(NULL, 0, soaker, state, NULL, &tid) != 0)
			goto bad;

		while (state->soak_state == SOAK_PAUSE)
			(void) cond_wait(&state->soak_cv,
			    &state->soak_lock);
		(void) mutex_unlock(&state->soak_lock);

		/*
		 * If the soaker needs to pause for the first set, stop it now.
		 */
		if (cpc_setgrp_sysonly(sgrp) == 0) {
			(void) mutex_lock(&state->soak_lock);
			state->soak_state = SOAK_PAUSE;
			(void) mutex_unlock(&state->soak_lock);
		}
	}
	if (cpc_bind_cpu(cpc, state->cpuid, this, 0) == -1)
		goto bad;

	for (nsamples = opts->nsamples; nsamples; nsamples--, sample_cnt++) {
		hrtime_t htnow;
		struct timespec ts;

		nreqs = cpc_setgrp_getbufs(sgrp, &data1, &data2, &scratch);

		ht += htdelta;
		htnow = gethrtime();
		if (ht <= htnow)
			continue;
		ts.tv_sec = (time_t)((ht - htnow) / NSECS_PER_SEC);
		ts.tv_nsec = (suseconds_t)((ht - htnow) % NSECS_PER_SEC);

		(void) nanosleep(&ts, NULL);

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
				goto bad;
			cpc_buf_sub(cpc, *scratch, *data1, *data2);

			print_sample(state->cpuid, *scratch, nreqs, name, 0);
		} else {
			/*
			 * More than one set is in use (multiple -c options
			 * given). Buffer usage in this case is:
			 *
			 * data1 = total counts for this set since program began
			 * data2 = unused
			 * scratch = most recent data snapshot
			 */
			name = cpc_setgrp_getname(sgrp);
			nreqs = cpc_setgrp_getbufs(sgrp, &data1, &data2,
			    &scratch);

			if (cpc_set_sample(cpc, this, *scratch) != 0)
				goto bad;

			cpc_buf_add(cpc, *data1, *data1, *scratch);

			if (cpc_unbind(cpc, this) != 0)
				(void) fprintf(stderr, gettext("%s: error "
				    "unbinding on cpu %d - %s\n"),
				    opts->pgmname, state->cpuid,
				    strerror(errno));

			this = cpc_setgrp_nextset(sgrp);

			print_sample(state->cpuid, *scratch, nreqs, name, 0);

			/*
			 * If periodic behavior was requested, rest here.
			 */
			if (opts->doperiod && opts->mseconds_rest > 0 &&
			    (sample_cnt % opts->nsets) == 0) {
				/*
				 * Stop the soaker while the tool rests.
				 */
				if (opts->dosoaker) {
					(void) mutex_lock(&state->soak_lock);
					if (state->soak_state == SOAK_RUN)
						state->soak_state = SOAK_PAUSE;
					(void) mutex_unlock(&state->soak_lock);
				}

				htnow = gethrtime();
				ht += restdelta;
				ts.tv_sec = (time_t)((ht - htnow) /
				    NSECS_PER_SEC);
				ts.tv_nsec = (suseconds_t)((ht - htnow) %
				    NSECS_PER_SEC);

				(void) nanosleep(&ts, NULL);
			}

			/*
			 * Start or stop the soaker if needed.
			 */
			if (opts->dosoaker) {
				(void) mutex_lock(&state->soak_lock);
				if (cpc_setgrp_sysonly(sgrp) &&
				    state->soak_state == SOAK_PAUSE) {
					/*
					 * Soaker is paused but the next set is
					 * sysonly: start the soaker.
					 */
					state->soak_state = SOAK_RUN;
					(void) cond_signal(&state->soak_cv);
				} else if (cpc_setgrp_sysonly(sgrp) == 0 &&
				    state->soak_state == SOAK_RUN)
					/*
					 * Soaker is running but the next set
					 * counts user events: stop the soaker.
					 */
					state->soak_state = SOAK_PAUSE;
				(void) mutex_unlock(&state->soak_lock);
			}

			if (cpc_bind_cpu(cpc, state->cpuid, this, 0) != 0)
				goto bad;
		}
	}

	if (cpc_unbind(cpc, this) != 0)
		(void) fprintf(stderr, gettext("%s: error unbinding on"
		    " cpu %d - %s\n"), opts->pgmname,
		    state->cpuid, strerror(errno));

	/*
	 * We're done, so stop the soaker if needed.
	 */
	if (opts->dosoaker) {
		(void) mutex_lock(&state->soak_lock);
		if (state->soak_state == SOAK_RUN)
			state->soak_state = SOAK_PAUSE;
		(void) mutex_unlock(&state->soak_lock);
	}

	return (NULL);
bad:
	state->status = 3;
	errstr = strerror(errno);
	(void) fprintf(stderr, gettext("%s: cpu%d - %s\n"),
	    opts->pgmname, state->cpuid, errstr);
	return (NULL);
}

static int
cpustat(void)
{
	cpc_setgrp_t	*accum;
	cpc_set_t	*start;
	int		c, i, retval;
	int		lwps = 0;
	psetid_t	mypset, cpupset;
	char		*errstr;
	cpc_buf_t	**data1, **data2, **scratch;
	int		nreqs;
	kstat_ctl_t	*kc;

	ncpus = (int)sysconf(_SC_NPROCESSORS_CONF);
	if ((gstate = calloc(ncpus, sizeof (*gstate))) == NULL) {
		(void) fprintf(stderr, gettext(
		    "%s: out of heap\n"), opts->pgmname);
		return (1);
	}

	max_chip_id = sysconf(_SC_CPUID_MAX);
	if ((chip_designees = malloc(max_chip_id * sizeof (int))) == NULL) {
		(void) fprintf(stderr, gettext(
		    "%s: out of heap\n"), opts->pgmname);
		return (1);
	}
	for (i = 0; i < max_chip_id; i++)
		chip_designees[i] = -1;

	if (smt) {
		if ((kc = kstat_open()) == NULL) {
			(void) fprintf(stderr, gettext(
			    "%s: kstat_open() failed: %s\n"), opts->pgmname,
			    strerror(errno));
			return (1);
		}
	}

	if (opts->dosoaker)
		if (priocntl(0, 0, PC_GETCID, &fxinfo) == -1) {
			(void) fprintf(stderr, gettext(
			    "%s: couldn't get FX scheduler class: %s\n"),
			    opts->pgmname, strerror(errno));
			return (1);
		}

	/*
	 * Only include processors that are participating in the system
	 */
	for (c = 0, i = 0; i < ncpus; c++) {
		switch (p_online(c, P_STATUS)) {
		case P_ONLINE:
		case P_NOINTR:
			if (smt) {

				gstate[i].chip_id = get_chipid(kc, c);
				if (gstate[i].chip_id != -1 &&
				    chip_designees[gstate[i].chip_id] == -1)
					chip_designees[gstate[i].chip_id] = c;
			}

			gstate[i++].cpuid = c;
			break;
		case P_OFFLINE:
		case P_POWEROFF:
		case P_FAULTED:
		case P_SPARE:
			gstate[i++].cpuid = -1;
			break;
		default:
			gstate[i++].cpuid = -1;
			(void) fprintf(stderr,
			    gettext("%s: cpu%d in unknown state\n"),
			    opts->pgmname, c);
			break;
		case -1:
			break;
		}
	}

	/*
	 * Examine the processor sets; if we're in one, only attempt
	 * to report on the set we're in.
	 */
	if (pset_bind(PS_QUERY, P_PID, P_MYID, &mypset) == -1) {
		errstr = strerror(errno);
		(void) fprintf(stderr, gettext("%s: pset_bind - %s\n"),
		    opts->pgmname, errstr);
	} else {
		for (i = 0; i < ncpus; i++) {
			struct tstate *this = &gstate[i];

			if (this->cpuid == -1)
				continue;

			if (pset_assign(PS_QUERY,
			    this->cpuid, &cpupset) == -1) {
				errstr = strerror(errno);
				(void) fprintf(stderr,
				    gettext("%s: pset_assign - %s\n"),
				    opts->pgmname, errstr);
				continue;
			}

			if (mypset != cpupset)
				this->cpuid = -1;
		}
	}

	if (opts->dotitle)
		print_title(opts->master);
	zerotime();

	for (i = 0; i < ncpus; i++) {
		struct tstate *this = &gstate[i];

		if (this->cpuid == -1)
			continue;
		this->sgrp = cpc_setgrp_clone(opts->master);
		if (this->sgrp == NULL) {
			this->cpuid = -1;
			continue;
		}
		if (thr_create(NULL, 0, gtick, this,
		    THR_BOUND|THR_NEW_LWP, &this->tid) == 0)
			lwps++;
		else {
			(void) fprintf(stderr,
			    gettext("%s: cannot create thread for cpu%d\n"),
			    opts->pgmname, this->cpuid);
			this->status = 4;
		}
	}

	if (lwps != 0)
		for (i = 0; i < ncpus; i++)
			(void) thr_join(gstate[i].tid, NULL, NULL);

	if ((accum = cpc_setgrp_clone(opts->master)) == NULL) {
		(void) fprintf(stderr, gettext("%s: out of heap\n"),
		    opts->pgmname);
		return (1);
	}

	retval = 0;
	for (i = 0; i < ncpus; i++) {
		struct tstate *this = &gstate[i];

		if (this->cpuid == -1)
			continue;
		cpc_setgrp_accum(accum, this->sgrp);
		cpc_setgrp_free(this->sgrp);
		this->sgrp = NULL;
		if (this->status != 0)
			retval = 1;
	}

	cpc_setgrp_reset(accum);
	start = cpc_setgrp_getset(accum);
	do {
		nreqs = cpc_setgrp_getbufs(accum, &data1, &data2, &scratch);
		print_total(lwps, *data1, nreqs, cpc_setgrp_getname(accum));
	} while (cpc_setgrp_nextset(accum) != start);

	cpc_setgrp_free(accum);
	accum = NULL;

	free(gstate);
	return (retval);
}

static int
get_chipid(kstat_ctl_t *kc, processorid_t cpuid)
{
	kstat_t		*ksp;
	kstat_named_t	*k;

	if ((ksp = kstat_lookup(kc, "cpu_info", cpuid, NULL)) == NULL)
		return (-1);

	if (kstat_read(kc, ksp, NULL) == -1) {
		(void) fprintf(stderr,
		    gettext("%s: kstat_read() failed for cpu %d: %s\n"),
		    opts->pgmname, cpuid, strerror(errno));
		return (-1);
	}

	if ((k = (kstat_named_t *)kstat_data_lookup(ksp, "chip_id")) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: chip_id not found for cpu %d: %s\n"),
		    opts->pgmname, cpuid, strerror(errno));
		return (-1);
	}

	return (k->value.i32);
}

static void *
soaker(void *arg)
{
	struct tstate	*state = arg;
	pcparms_t	pcparms;
	fxparms_t	*fx = (fxparms_t *)pcparms.pc_clparms;

	if (processor_bind(P_LWPID, P_MYID, state->cpuid, NULL) != 0)
		(void) fprintf(stderr, gettext("%s: couldn't bind soaker "
		    "thread to cpu%d: %s\n"), opts->pgmname, state->cpuid,
		    strerror(errno));

	/*
	 * Put the soaker thread in the fixed priority (FX) class so it runs
	 * at the lowest possible global priority.
	 */
	pcparms.pc_cid = fxinfo.pc_cid;
	fx->fx_upri = 0;
	fx->fx_uprilim = 0;
	fx->fx_tqsecs = fx->fx_tqnsecs = FX_TQDEF;

	if (priocntl(P_LWPID, P_MYID, PC_SETPARMS, &pcparms) != 0)
		(void) fprintf(stderr, gettext("%s: couldn't put soaker "
		    "thread in FX sched class: %s\n"), opts->pgmname,
		    strerror(errno));

	/*
	 * Let the parent thread know we're ready to roll.
	 */
	(void) mutex_lock(&state->soak_lock);
	state->soak_state = SOAK_RUN;
	(void) cond_signal(&state->soak_cv);
	(void) mutex_unlock(&state->soak_lock);

	for (;;) {
spin:
		(void) mutex_lock(&state->soak_lock);
		if (state->soak_state == SOAK_RUN) {
			(void) mutex_unlock(&state->soak_lock);
			goto spin;
		}

		while (state->soak_state == SOAK_PAUSE)
			(void) cond_wait(&state->soak_cv,
			    &state->soak_lock);
		(void) mutex_unlock(&state->soak_lock);
	}

	/*NOTREACHED*/
	return (NULL);
}
