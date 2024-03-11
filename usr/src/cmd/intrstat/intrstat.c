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

#include <stdio.h>
#include <stdarg.h>
#include <dtrace.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <strings.h>
#include <termio.h>
#include <signal.h>
#include <locale.h>

#include "statcommon.h"

#define	INTRSTAT_COLUMN_OFFS		14
#define	INTRSTAT_COLUMNS_PER_CPU	15
#define	INTRSTAT_CPUS_PER_LINE(w)	\
	(((w) - INTRSTAT_COLUMN_OFFS) / INTRSTAT_COLUMNS_PER_CPU)
#define	INTRSTAT_OPTSTR			"x:c:C:T:"

static uint_t timestamp_fmt = NODATE;

#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"		/* Use this only if it isn't */
#endif

static dtrace_hdl_t *g_dtp;
static int *g_present;
static int g_max_cpus;
static int g_start, g_end;
static int g_header;
static long g_sleeptime = 1;
static hrtime_t g_interval = NANOSEC;
static int g_intr;
static psetid_t g_pset = PS_NONE;
static processorid_t *g_pset_cpus;
static uint_t g_pset_ncpus;
static int g_cpus_per_line = INTRSTAT_CPUS_PER_LINE(80);

static const char *g_pname = "intrstat";
static const char *g_prog =
"interrupt-start"
"/arg0 != NULL/"
"{"
"	self->ts = vtimestamp;"
"}"
""
"interrupt-complete"
"/self->ts/"
"{"
"	this->devi = (struct dev_info *)arg0;"
"	@counts[stringof(`devnamesp[this->devi->devi_major].dn_name),"
"	     this->devi->devi_instance] = count();"
"	@times[stringof(`devnamesp[this->devi->devi_major].dn_name),"
"	     this->devi->devi_instance] = sum(vtimestamp - self->ts);"
"	self->ts = 0;"
"}";

static void
usage(void)
{
	(void) fprintf(stderr,
	    "usage:  intrstat [ -C psrset | -c cpulist ]  [-x opt[=val]] "
	    "[-T d|u] [interval [ count]]\n");

	exit(EXIT_FAILURE);
}

static void
fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	(void) fprintf(stderr, "%s: ", g_pname);
	(void) vfprintf(stderr, fmt, ap);

	if (fmt[strlen(fmt) - 1] != '\n')
		(void) fprintf(stderr, ": %s\n",
		    dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));

	exit(EXIT_FAILURE);
}

/*ARGSUSED*/
static void
intr(int signo)
{
	g_intr++;
}

static void
status(int signal __unused)
{
}

static void
set_width(int sig __unused)
{
	struct winsize win;

	if (!isatty(fileno(stdout)))
		return;

	if (ioctl(fileno(stdout), TIOCGWINSZ, &win) == -1)
		return;

	if (win.ws_col == 0) {
		/*
		 * If TIOCGWINSZ returned 0 for the columns, just return --
		 * thereby using the default value of g_cpus_per_line.  (This
		 * happens, e.g., when running over a tip line.)
		 */
		return;
	}

	g_cpus_per_line = INTRSTAT_CPUS_PER_LINE(win.ws_col);

	if (g_cpus_per_line < 1)
		g_cpus_per_line = 1;
}

static void
print_header()
{
	int i, j;
	char c[256];

	if (!g_header)
		return;

	(void) printf("\n%12s |", "device");
	for (i = g_start, j = 0; i < g_max_cpus; i++) {
		if (!g_present[i])
			continue;

		(void) sprintf(c, "cpu%d", i);
		(void) printf(" %9s %%tim", c);

		if (++j >= g_cpus_per_line)
			break;
	}

	(void) printf("\n-------------+");

	while (j--)
		(void) printf("---------------");

	(void) printf("\n");
	g_header = 0;
}

/*ARGSUSED*/
static int
walk(const dtrace_aggdata_t *data, void *arg)
{
	dtrace_aggdesc_t *aggdesc = data->dtada_desc;
	dtrace_recdesc_t *nrec, *irec;
	char *name, c[256];
	int32_t *instance;
	static const dtrace_aggdata_t *count;
	int i, j;

	if (count == NULL) {
		count = data;
		return (DTRACE_AGGWALK_NEXT);
	}

	nrec = &aggdesc->dtagd_rec[1];
	irec = &aggdesc->dtagd_rec[2];

	name = data->dtada_data + nrec->dtrd_offset;
	/* LINTED - alignment */
	instance = (int32_t *)(data->dtada_data + irec->dtrd_offset);

	for (i = g_start, j = 0; i < g_max_cpus && j < g_cpus_per_line; i++) {
		/* LINTED - alignment */
		uint64_t time = *((uint64_t *)(data->dtada_percpu[i]));
		/* LINTED - alignment */
		uint64_t n = *((uint64_t *)(count->dtada_percpu[i]));

		if (!g_present[i])
			continue;

		if (j++ == 0) {
			print_header();
			(void) snprintf(c, sizeof (c), "%s#%d",
			    name, *instance);
			(void) printf("%12s |", c);
		}

		(void) printf(" %9lld %4.1f",
		    (unsigned long long)((double)n /
		    ((double)g_interval / (double)NANOSEC)),
		    ((double)time * (double)100.0) / (double)g_interval);
	}

	(void) printf(j ? "\n" : "");
	g_end = i;
	count = NULL;
	return (DTRACE_AGGWALK_NEXT);
}

static void
select_cpu(processorid_t cpu)
{
	if (g_pset != PS_NONE)
		fatal("cannot specify both a processor set and a processor\n");

	if (cpu < 0 || cpu >= g_max_cpus)
		fatal("cpu %d out of range\n", cpu);

	if (p_online(cpu, P_STATUS) == -1) {
		if (errno != EINVAL)
			fatal("could not get status for cpu %d", cpu);
		fatal("cpu %d not present\n", cpu);
	}

	g_present[cpu] = 1;
}

static void
select_cpus(processorid_t low, processorid_t high)
{
	if (g_pset != PS_NONE)
		fatal("cannot specify both a processor set and processors\n");

	if (low < 0 || low >= g_max_cpus)
		fatal("invalid cpu '%d'\n", low);

	if (high < 0 || high >= g_max_cpus)
		fatal("invalid cpu '%d'\n", high);

	if (low >= high)
		fatal("invalid range '%d' to '%d'\n", low, high);

	do {
		if (p_online(low, P_STATUS) != -1)
			g_present[low] = 1;
	} while (++low <= high);
}

static void
select_pset(psetid_t pset)
{
	processorid_t i;

	if (pset < 0)
		fatal("processor set %d is out of range\n", pset);

	/*
	 * Only one processor set can be specified.
	 */
	if (g_pset != PS_NONE)
		fatal("at most one processor set may be specified\n");

	/*
	 * One cannot select processors _and_ a processor set.
	 */
	for (i = 0; i < g_max_cpus; i++)
		if (g_present[i])
			break;

	if (i != g_max_cpus)
		fatal("cannot specify both a processor and a processor set\n");

	g_pset = pset;
	g_pset_ncpus = g_max_cpus;

	if (pset_info(g_pset, NULL, &g_pset_ncpus, g_pset_cpus) == -1)
		fatal("invalid processor set: %d\n", g_pset);

	if (g_pset_ncpus == 0)
		fatal("processor set %d empty\n", g_pset);

	for (i = 0; i < g_pset_ncpus; i++)
		g_present[g_pset_cpus[i]] = 1;
}

static void
check_pset(void)
{
	uint_t ncpus = g_max_cpus;
	processorid_t i;

	if (g_pset == PS_NONE)
		return;

	if (pset_info(g_pset, NULL, &ncpus, g_pset_cpus) == -1) {
		if (errno == EINVAL)
			fatal("processor set %d destroyed\n", g_pset);

		fatal("couldn't get info for processor set %d", g_pset);
	}

	if (ncpus == 0)
		fatal("processor set %d empty\n", g_pset);

	if (ncpus == g_pset_ncpus) {
		for (i = 0; i < g_pset_ncpus; i++) {
			if (!g_present[g_pset_cpus[i]])
				break;
		}

		/*
		 * If the number of CPUs hasn't changed, and every CPU
		 * in the processor set is also selected, we know that the
		 * processor set itself hasn't changed.
		 */
		if (i == g_pset_ncpus)
			return;
	}

	/*
	 * If we're here, we have a new processor set.  First, we need
	 * to zero out the present array.
	 */
	bzero(g_present, sizeof (processorid_t) * g_max_cpus);

	g_pset_ncpus = ncpus;

	for (i = 0; i < g_pset_ncpus; i++)
		g_present[g_pset_cpus[i]] = 1;
}

int
main(int argc, char **argv)
{
	dtrace_prog_t *prog;
	dtrace_proginfo_t info;
	int err, i, indefinite = 1;
	long iter;
	processorid_t id;
	struct sigaction act;
	struct itimerspec ts;
	struct sigevent ev;
	sigset_t set;
	timer_t tid;
	char *end, *p;
	int c;
	hrtime_t last, now;
	dtrace_optval_t statustime;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = set_width;
	(void) sigaction(SIGWINCH, &act, NULL);

	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = intr;
	(void) sigaction(SIGUSR1, &act, NULL);

	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = status;
	(void) sigaction(SIGUSR2, &act, NULL);

	act.sa_handler = set_width;
	(void) sigaction(SIGWINCH, &act, NULL);
	set_width(0);

	(void) sigemptyset(&set);
	(void) sigaddset(&set, SIGUSR1);
	(void) sigaddset(&set, SIGWINCH);
	(void) sigprocmask(SIG_BLOCK, &set, NULL);

	ev.sigev_notify = SIGEV_SIGNAL;
	ev.sigev_signo = SIGUSR1;

	if (timer_create(CLOCK_REALTIME, &ev, &tid) == -1)
		fatal("cannot create CLOCK_HIGHRES timer");

	g_max_cpus = sysconf(_SC_CPUID_MAX) + 1;

	if ((g_present = malloc(sizeof (processorid_t) * g_max_cpus)) == NULL)
		fatal("could not allocate g_present array\n");

	bzero(g_present, sizeof (processorid_t) * g_max_cpus);

	g_pset_cpus = malloc(sizeof (processorid_t) * g_max_cpus);
	if (g_pset_cpus == NULL)
		fatal("could not allocate g_pset_cpus");

	bzero(g_pset_cpus, sizeof (processorid_t) * g_max_cpus);

	while ((c = getopt(argc, argv, INTRSTAT_OPTSTR)) != EOF) {
		switch (c) {
		case 'c': {
			/*
			 * We allow CPUs to be specified as an optionally
			 * comma separated list of either CPU IDs or ranges
			 * of CPU IDs.
			 */
			char *s = strtok(optarg, ",");

			while (s != NULL) {
				id = strtoul(s, &end, 0);

				if (id == ULONG_MAX && errno == ERANGE) {
					*end = '\0';
					fatal("invalid cpu '%s'\n", s);
				}

				if (*(s = end) != '\0') {
					processorid_t p;

					if (*s != '-')
						fatal("invalid cpu '%s'\n", s);
					p = strtoul(++s, &end, 0);

					if (*end != '\0' ||
					    (p == ULONG_MAX && errno == ERANGE))
						fatal("invalid cpu '%s'\n", s);

					select_cpus(id, p);
				} else {
					select_cpu(id);
				}

				s = strtok(NULL, ",");
			}

			break;
		}

		case 'C': {
			psetid_t pset = strtoul(optarg, &end, 0);

			if (*end != '\0' ||
			    (pset == ULONG_MAX && errno == ERANGE))
				fatal("invalid processor set '%s'\n", optarg);

			select_pset(pset);
			break;
		}

		case 'T':
			if (optarg) {
				if (*optarg == 'u')
					timestamp_fmt = UDATE;
				else if (*optarg == 'd')
					timestamp_fmt = DDATE;
				else
					usage();
			} else {
				usage();
			}
			break;

		default:
			if (strchr(INTRSTAT_OPTSTR, c) == NULL)
				usage();
		}
	}

	if ((g_dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL) {
		fatal("cannot open dtrace library: %s\n",
		    dtrace_errmsg(NULL, err));
	}

	if ((prog = dtrace_program_strcompile(g_dtp, g_prog,
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL)) == NULL)
		fatal("invalid program");

	if (dtrace_program_exec(g_dtp, prog, &info) == -1)
		fatal("failed to enable probes");

	if (dtrace_setopt(g_dtp, "aggsize", "128k") == -1)
		fatal("failed to set 'aggsize'");

	if (dtrace_setopt(g_dtp, "aggrate", "0") == -1)
		fatal("failed to set 'aggrate'");

	if (dtrace_setopt(g_dtp, "aggpercpu", 0) == -1)
		fatal("failed to set 'aggpercpu'");

	optind = 1;
	while ((c = getopt(argc, argv, INTRSTAT_OPTSTR)) != EOF) {
		switch (c) {
		case 'x':
			if ((p = strchr(optarg, '=')) != NULL)
				*p++ = '\0';

			if (dtrace_setopt(g_dtp, optarg, p) != 0)
				fatal("failed to set -x %s", optarg);
			break;
		}
	}

	if (optind != argc) {
		g_sleeptime = strtol(argv[optind], &end, 10);

		if (*end != '\0' || g_sleeptime == 0)
			fatal("invalid interval '%s'\n", argv[1]);

		if (g_sleeptime <= 0)
			fatal("interval must be greater than zero.\n");

		if (g_sleeptime == LONG_MAX && errno == ERANGE)
			fatal("invalid interval '%s'\n", argv[optind]);

		if (++optind != argc) {
			char *s = argv[optind];

			iter = strtol(s, &end, 0);
			indefinite = 0;

			if (*end != '\0' || iter <= 0 ||
			    (iter == LONG_MAX && errno == ERANGE))
				fatal("invalid count '%s'\n", s);
		}
	}

	ts.it_value.tv_sec = g_sleeptime;
	ts.it_value.tv_nsec = 0;
	ts.it_interval.tv_sec = g_sleeptime;
	ts.it_interval.tv_nsec = 0;

	if (timer_settime(tid, TIMER_RELTIME, &ts, NULL) == -1)
		fatal("cannot set time on CLOCK_REALTIME timer");

	for (i = 0; i < g_max_cpus && !g_present[i]; i++)
		continue;

	if (i == g_max_cpus) {
		for (i = 0; i < g_max_cpus; i++)
			g_present[i] = p_online(i, P_STATUS) == -1 ? 0 : 1;
	}

	if (dtrace_go(g_dtp) != 0)
		fatal("dtrace_go()");

	last = gethrtime();

	if (dtrace_getopt(g_dtp, "statusrate", &statustime) == -1)
		fatal("failed to get 'statusrate'");

	if (statustime < ((dtrace_optval_t)g_sleeptime * NANOSEC)) {
		ev.sigev_notify = SIGEV_SIGNAL;
		ev.sigev_signo = SIGUSR2;

		if (timer_create(CLOCK_REALTIME, &ev, &tid) == -1)
			fatal("cannot create status timer");

		ts.it_value.tv_sec = statustime / NANOSEC;
		ts.it_value.tv_nsec = statustime % NANOSEC;
		ts.it_interval = ts.it_value;

		if (timer_settime(tid, TIMER_RELTIME, &ts, NULL) == -1)
			fatal("cannot set time on status timer");
	}

	(void) sigemptyset(&set);

	while (indefinite || iter) {

		(void) sigsuspend(&set);

		if (dtrace_status(g_dtp) == -1)
			fatal("dtrace_status()");

		if (g_intr == 0)
			continue;

		iter--;
		g_intr--;
		check_pset();

		now = gethrtime();
		g_interval = now - last;
		last = now;

		if (dtrace_aggregate_snap(g_dtp) != 0)
			fatal("failed to add to aggregate");

		g_start = g_end = 0;

		if (timestamp_fmt != NODATE)
			print_timestamp(timestamp_fmt);

		do {
			g_header = 1;

			if (dtrace_aggregate_walk_keyvarsorted(g_dtp,
			    walk, NULL) != 0)
				fatal("failed to sort aggregate");

			if (g_start == g_end)
				break;
		} while ((g_start = g_end) < g_max_cpus);

		dtrace_aggregate_clear(g_dtp);
	}

	return (0);
}
