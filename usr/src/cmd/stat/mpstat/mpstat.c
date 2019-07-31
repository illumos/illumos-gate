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

#include <sys/pset.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/sysinfo.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <memory.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <errno.h>
#include <kstat.h>
#include <poll.h>
#include <signal.h>
#include <locale.h>

#include "statcommon.h"

#define	SNAP(s, i, l, n)	((s) ? agg_proc_snap(s, i, l, n) : 0)

#define	REPRINT		20

char *cmdname = "mpstat";
int caught_cont = 0;

static uint_t timestamp_fmt = NODATE;

static int hz;
static int display_pset = -1;
static int show_set = 0;
static int suppress_state;

static void print_header(int, int);
static void show_cpu_usage(struct snapshot *, struct snapshot *, int);
static void usage(void);

int
main(int argc, char **argv)
{
	int c;
	int display_agg = 0;
	int iter = 1;
	int interval = 0;
	char *endptr;
	int infinite_cycles = 0;
	kstat_ctl_t *kc;
	struct snapshot *old = NULL;
	struct snapshot *new = NULL;
	enum snapshot_types types = SNAP_CPUS;
	hrtime_t start_n;
	hrtime_t period_n;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"		/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "apP:qT:")) != (int)EOF)
		switch (c) {
			case 'a':
				/*
				 * Display aggregate data for processor sets.
				 */
				display_agg = 1;
				break;
			case 'p':
				/*
				 * Display all processor sets.
				 */
				if (display_pset != -1)
					usage();
				show_set = 1;
				break;
			case 'P':
				/*
				 * Display specific processor set.
				 */
				if (show_set == 1)
					usage();
				display_pset = (int)strtol
				    (optarg, &endptr, 10);
				if (*endptr != '\0')
					usage();
				/*
				 * Not valid to specify a negative processor
				 * set value.
				 */
				if (display_pset < 0)
					usage();
				break;
			case 'q':
				suppress_state = 1;
				break;
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
			case '?':
				usage();
				break;
		}

	hz = sysconf(_SC_CLK_TCK);

	if (argc > optind) {
		interval = (int)strtol(argv[optind], &endptr, 10);
		if (*endptr != '\0')
			usage();
		period_n = (hrtime_t)interval * NANOSEC;
		if (argc > optind + 1) {
			iter = (unsigned int)strtoul
			    (argv[optind + 1], &endptr, 10);
			if (*endptr != '\0' || iter < 0)
				usage();
			if (iter == 0)
				return (0);
		} else {
			infinite_cycles = 1;
		}
	}

	if (display_agg || show_set || display_pset != -1)
		types |= SNAP_PSETS;

	kc = open_kstat();

	/* Set up handler for SIGCONT */
	if (signal(SIGCONT, cont_handler) == SIG_ERR)
		fail(1, "signal failed");

	start_n = gethrtime();

	while (infinite_cycles || iter > 0) {
		free_snapshot(old);
		old = new;
		new = acquire_snapshot(kc, types, NULL);

		if (!suppress_state)
			snapshot_report_changes(old, new);

		/* if config changed, show stats from boot */
		if (snapshot_has_changed(old, new)) {
			free_snapshot(old);
			old = NULL;
		}

		show_cpu_usage(old, new, display_agg);

		if (!infinite_cycles && --iter < 1)
			break;

		/* Have a kip */
		sleep_until(&start_n, period_n, infinite_cycles, &caught_cont);
	}
	(void) kstat_close(kc);

	return (0);
}

/*
 * Print an mpstat output header.
 */
static void
print_header(int display_agg, int show_set)
{
	if (display_agg == 1)
		(void) printf("SET minf mjf xcal  intr ithr  csw icsw migr "
		    "smtx  srw syscl  usr sys  wt idl sze");
	else {
		(void) printf("CPU minf mjf xcal  intr ithr  csw icsw migr "
		    "smtx  srw syscl  usr sys  wt idl");
		if (show_set == 1)
			(void) printf(" set");
	}
	(void) printf("\n");
}

static void
print_cpu(struct cpu_snapshot *c1, struct cpu_snapshot *c2)
{
	uint64_t ticks = 0;
	double etime, percent;
	kstat_t *old_vm = NULL;
	kstat_t *old_sys = NULL;

	if (display_pset != -1 && display_pset != c2->cs_pset_id)
		return;

	/*
	 * the first mpstat output will have c1 = NULL, to give
	 * results since boot
	 */
	if (c1) {
		old_vm = &c1->cs_vm;
		old_sys = &c1->cs_sys;

		/* check there are stats to report */
		if (!CPU_ACTIVE(c1))
			return;
	}

	/* check there are stats to report */
	if (!CPU_ACTIVE(c2))
		return;

	ticks = cpu_ticks_delta(old_sys, &c2->cs_sys);

	etime = (double)ticks / hz;
	if (etime == 0.0) /* Prevent divide by zero errors */
		etime = 1.0;
	percent = 100.0 / etime / hz;

	(void) printf("%3d %4.0f %3.0f %4.0f %5.0f %4.0f "
	    "%4.0f %4.0f %4.0f %4.0f %4.0f %5.0f  %3.0f %3.0f "
	    "%3.0f %3.0f",
	    c2->cs_id,
	    (kstat_delta(old_vm, &c2->cs_vm, "hat_fault") +
	    kstat_delta(old_vm, &c2->cs_vm, "as_fault")) / etime,
	    kstat_delta(old_vm, &c2->cs_vm, "maj_fault") / etime,
	    kstat_delta(old_sys, &c2->cs_sys, "xcalls") / etime,
	    kstat_delta(old_sys, &c2->cs_sys, "intr") / etime,
	    kstat_delta(old_sys, &c2->cs_sys, "intrthread") / etime,
	    kstat_delta(old_sys, &c2->cs_sys, "pswitch") / etime,
	    kstat_delta(old_sys, &c2->cs_sys, "inv_swtch") / etime,
	    kstat_delta(old_sys, &c2->cs_sys, "cpumigrate") / etime,
	    kstat_delta(old_sys, &c2->cs_sys, "mutex_adenters") / etime,
	    (kstat_delta(old_sys, &c2->cs_sys, "rw_rdfails") +
	    kstat_delta(old_sys, &c2->cs_sys, "rw_wrfails")) / etime,
	    kstat_delta(old_sys, &c2->cs_sys, "syscall") / etime,
	    kstat_delta(old_sys, &c2->cs_sys, "cpu_ticks_user") * percent,
	    kstat_delta(old_sys, &c2->cs_sys, "cpu_ticks_kernel") * percent,
	    kstat_delta(old_sys, &c2->cs_sys, "cpu_ticks_wait") * percent,
	    kstat_delta(old_sys, &c2->cs_sys, "cpu_ticks_idle") * percent);

	if (show_set)
		(void) printf(" %3d", c2->cs_pset_id);
	(void) printf("\n");
}

/*ARGSUSED*/
static void
compare_cpu(void *v1, void *v2, void *data)
{
	struct cpu_snapshot *c1 = (struct cpu_snapshot *)v1;
	struct cpu_snapshot *c2 = (struct cpu_snapshot *)v2;

	if (c2 == NULL)
		return;

	print_cpu(c1, c2);
}

static int
pset_has_stats(struct pset_snapshot *p)
{
	int count = 0;
	size_t i;
	for (i = 0; i < p->ps_nr_cpus; i++) {
		if (CPU_ACTIVE(p->ps_cpus[i]))
			count++;
	}
	return (count);
}

static void
agg_stat(kstat_t *k1, kstat_t *k2, char *name)
{
	kstat_named_t *ksn = kstat_data_lookup(k1, name);
	kstat_named_t *ksn2 = kstat_data_lookup(k2, name);
	ksn->value.ui64 += ksn2->value.ui64;
}

static kstat_t *
agg_vm(struct pset_snapshot *p, kstat_t *ks)
{
	size_t i;

	if (p->ps_nr_cpus == 0)
		return (NULL);

	if (kstat_copy(&p->ps_cpus[0]->cs_vm, ks))
		return (NULL);

	for (i = 1; i < p->ps_nr_cpus; i++) {
		agg_stat(ks, &p->ps_cpus[i]->cs_vm, "hat_fault");
		agg_stat(ks, &p->ps_cpus[i]->cs_vm, "as_fault");
		agg_stat(ks, &p->ps_cpus[i]->cs_vm, "maj_fault");
	}

	return (ks);
}

static kstat_t *
agg_sys(struct pset_snapshot *p, kstat_t *ks)
{
	size_t i;

	if (p->ps_nr_cpus == 0)
		return (NULL);

	if (kstat_copy(&p->ps_cpus[0]->cs_sys, ks))
		return (NULL);

	for (i = 1; i < p->ps_nr_cpus; i++) {
		agg_stat(ks, &p->ps_cpus[i]->cs_sys, "xcalls");
		agg_stat(ks, &p->ps_cpus[i]->cs_sys, "intr");
		agg_stat(ks, &p->ps_cpus[i]->cs_sys, "intrthread");
		agg_stat(ks, &p->ps_cpus[i]->cs_sys, "pswitch");
		agg_stat(ks, &p->ps_cpus[i]->cs_sys, "inv_swtch");
		agg_stat(ks, &p->ps_cpus[i]->cs_sys, "cpumigrate");
		agg_stat(ks, &p->ps_cpus[i]->cs_sys, "mutex_adenters");
		agg_stat(ks, &p->ps_cpus[i]->cs_sys, "rw_rdfails");
		agg_stat(ks, &p->ps_cpus[i]->cs_sys, "rw_wrfails");
		agg_stat(ks, &p->ps_cpus[i]->cs_sys, "syscall");
		agg_stat(ks, &p->ps_cpus[i]->cs_sys, "cpu_ticks_user");
		agg_stat(ks, &p->ps_cpus[i]->cs_sys, "cpu_ticks_kernel");
		agg_stat(ks, &p->ps_cpus[i]->cs_sys, "cpu_ticks_wait");
		agg_stat(ks, &p->ps_cpus[i]->cs_sys, "cpu_ticks_idle");
	}

	return (ks);
}

static uint64_t
get_nr_ticks(struct pset_snapshot *p1, struct pset_snapshot *p2)
{
	kstat_t *old = NULL;
	kstat_t *new = NULL;
	size_t i = 0;

	for (i = 0; p1 && i < p1->ps_nr_cpus; i++) {
		if (p1->ps_cpus[i]->cs_sys.ks_data) {
			old = &p1->ps_cpus[i]->cs_sys;
			break;
		}
	}

	for (i = 0; p2 && i < p2->ps_nr_cpus; i++) {
		if (p2->ps_cpus[i]->cs_sys.ks_data) {
			new = &p2->ps_cpus[i]->cs_sys;
			break;
		}
	}

	if (old == NULL && new == NULL)
		return (0);

	if (new == NULL) {
		new = old;
		old = NULL;
	}

	return (cpu_ticks_delta(old, new));
}

static void
print_pset(struct pset_snapshot *p1, struct pset_snapshot *p2)
{
	uint64_t ticks = 0;
	double etime, percent;
	kstat_t old_vm;
	kstat_t old_sys;
	kstat_t new_vm;
	kstat_t new_sys;

	if (display_pset != -1 && display_pset != p2->ps_id)
		return;

	if ((p1 && !pset_has_stats(p1)) || !pset_has_stats(p2))
		return;

	old_vm.ks_data = old_sys.ks_data = NULL;
	new_vm.ks_data = new_sys.ks_data = NULL;

	/*
	 * FIXME: these aggs will count "new" or disappeared cpus
	 * in a set, leaving an apparent huge change.
	 */

	/*
	 * the first mpstat output will have p1 = NULL, to give
	 * results since boot
	 */
	if (p1) {
		if (!agg_vm(p1, &old_vm) || !agg_sys(p1, &old_sys))
			goto out;
	}

	if (!agg_vm(p2, &new_vm) || !agg_sys(p2, &new_sys))
		goto out;

	ticks = get_nr_ticks(p1, p2);

	etime = (double)ticks / hz;
	if (etime == 0.0) /* Prevent divide by zero errors */
		etime = 1.0;
	percent = 100.0 / p2->ps_nr_cpus / etime / hz;

	(void) printf("%3d %4.0f %3.0f %4.0f %5.0f %4.0f "
	    "%4.0f %4.0f %4.0f %4.0f %4.0f %5.0f  %3.0f %3.0f "
	    "%3.0f %3.0f %3d\n",
	    p2->ps_id,
	    (kstat_delta(&old_vm, &new_vm, "hat_fault") +
	    kstat_delta(&old_vm, &new_vm, "as_fault")) / etime,
	    kstat_delta(&old_vm, &new_vm, "maj_fault") / etime,
	    kstat_delta(&old_sys, &new_sys, "xcalls") / etime,
	    kstat_delta(&old_sys, &new_sys, "intr") / etime,
	    kstat_delta(&old_sys, &new_sys, "intrthread") / etime,
	    kstat_delta(&old_sys, &new_sys, "pswitch") / etime,
	    kstat_delta(&old_sys, &new_sys, "inv_swtch") / etime,
	    kstat_delta(&old_sys, &new_sys, "cpumigrate") / etime,
	    kstat_delta(&old_sys, &new_sys, "mutex_adenters") / etime,
	    (kstat_delta(&old_sys, &new_sys, "rw_rdfails") +
	    kstat_delta(&old_sys, &new_sys, "rw_wrfails")) / etime,
	    kstat_delta(&old_sys, &new_sys, "syscall") / etime,
	    kstat_delta(&old_sys, &new_sys, "cpu_ticks_user") * percent,
	    kstat_delta(&old_sys, &new_sys, "cpu_ticks_kernel") * percent,
	    kstat_delta(&old_sys, &new_sys, "cpu_ticks_wait") * percent,
	    kstat_delta(&old_sys, &new_sys, "cpu_ticks_idle") * percent,
	    p2->ps_nr_cpus);

out:
	free(old_vm.ks_data);
	free(old_sys.ks_data);
	free(new_vm.ks_data);
	free(new_sys.ks_data);
}

/*ARGSUSED*/
static void
compare_pset(void *v1, void *v2, void *data)
{
	struct pset_snapshot *p1 = (struct pset_snapshot *)v1;
	struct pset_snapshot *p2 = (struct pset_snapshot *)v2;

	if (p2 == NULL)
		return;

	print_pset(p1, p2);
}


/*
 * Report statistics for a sample interval.
 */
static void
show_cpu_usage(struct snapshot *old, struct snapshot *new, int display_agg)
{
	static int lines_until_reprint = 0;
	enum snapshot_types type = SNAP_CPUS;
	snapshot_cb cb = compare_cpu;

	if (timestamp_fmt != NODATE)
		print_timestamp(timestamp_fmt);

	if (lines_until_reprint == 0 || nr_active_cpus(new) > 1) {
		print_header(display_agg, show_set);
		lines_until_reprint = REPRINT;
	}

	lines_until_reprint--;

	if (display_agg) {
		type = SNAP_PSETS;
		cb = compare_pset;
	}

	/* print stats since boot the first time round */
	(void) snapshot_walk(type, old, new, cb, NULL);
	(void) fflush(stdout);
}

/*
 * Usage message on error.
 */
static void
usage(void)
{
	(void) fprintf(stderr,
	    "Usage: mpstat [-aq] [-p | -P processor_set] [-T d|u] "
	    "[interval [count]]\n");
	exit(1);
}
