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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "config.h"

#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>

#ifdef HAVE_SYSINFO
#include <sys/sysinfo.h>
#endif

#ifdef HAVE_LIBKSTAT
#include <kstat.h>
#include <sys/cpuvar.h>
#endif /* HAVE_LIBKSTAT */

#include <stdarg.h>

#include "filebench.h"
#include "flowop.h"
#include "vars.h"
#include "stats.h"

/*
 * A set of routines for collecting and dumping various filebench
 * run statistics.
 */

/* Global statistics */
static flowstat_t *globalstats = NULL;

static hrtime_t stats_cputime = 0;

#ifdef HAVE_LIBKSTAT
static kstat_ctl_t *kstatp = NULL;
static kstat_t *sysinfo_ksp = NULL;

/*
 * Uses the kstat library or, if it is not available, the /proc/stat file
 * to obtain cpu statistics. Collects statistics for each cpu, initializes
 * a local pointer to the sysinfo kstat, and returns the sum of user and
 * kernel time for all the cpus.
 */
static vinteger_t
kstats_read_cpu(void)
{
	int ncpus;
	kstat_t	**cpu_stat_list = NULL;
	ulong_t cputime_states[CPU_STATES];
	hrtime_t cputime;
	int i;

	kstat_t *ksp;

	if (kstatp == NULL) {
		if ((kstatp = kstat_open()) == (kstat_ctl_t *)NULL) {
			filebench_log(LOG_ERROR, "Cannot read kstats");
			return (-1);
		}
	}

	/*
	 * Per-CPU statistics
	 */

	ncpus = 0;
	for (ksp = kstatp->kc_chain; ksp; ksp = ksp->ks_next)
		if (strncmp(ksp->ks_name, "cpu_stat", 8) == 0)
			ncpus++;

	if ((cpu_stat_list =
	    (kstat_t **)malloc(ncpus * sizeof (kstat_t *))) == NULL) {
		filebench_log(LOG_ERROR, "malloc failed");
		return (-1);
	}

	ncpus = 0;
	for (ksp = kstatp->kc_chain; ksp; ksp = ksp->ks_next)
		if (strncmp(ksp->ks_name, "cpu_stat", 8) == 0 &&
		    kstat_read(kstatp, ksp, NULL) != -1)
			cpu_stat_list[ncpus++] = ksp;

	if (ncpus == 0) {
		filebench_log(LOG_ERROR,
		    "kstats can't find any cpu statistics");
		return (0);
	}

	if (sysinfo_ksp == NULL)
		sysinfo_ksp = kstat_lookup(kstatp, "unix", 0, "sysinfo");

	/* Sum across all CPUs */
	(void) memset(&cputime_states, 0, sizeof (cputime_states));
	for (i = 0; i < ncpus; i++) {
		cpu_stat_t cpu_stats;
		int j;

		(void) kstat_read(kstatp, cpu_stat_list[i],
		    (void *) &cpu_stats);
		for (j = 0; j < CPU_STATES; j++)
			cputime_states[j] += cpu_stats.cpu_sysinfo.cpu[j];
	}

	cputime = cputime_states[CPU_KERNEL] + cputime_states[CPU_USER];

	return (10000000LL * cputime);
}
#else /* HAVE_LIBKSTAT */
#ifdef HAVE_PROC_STAT
static FILE *statfd = 0;
vinteger_t
kstats_read_cpu(void)
{
	/*
	 * Linux provides system wide statistics in /proc/stat
	 * The entry for cpu is
	 * cpu  1636 67 1392 208671 5407 20 12
	 * cpu0 626 8 997 104476 2499 7 7
	 * cpu1 1010 58 395 104195 2907 13 5
	 *
	 * The number of jiffies (1/100ths of  a  second)  that  the
	 * system  spent  in  user mode, user mode with low priority
	 * (nice), system mode, and  the  idle  task,  respectively.
	 */
	unsigned int user, nice, system;
	char cpu[128]; /* placeholder to read "cpu" */
	if (statfd == 0) {
		statfd = fopen("/proc/stat", "r");
		if (statfd < 0) {
			filebench_log(LOG_ERROR, "Cannot open /proc/stat");
			return (-1);
		}
	}
	if (fscanf(statfd, "%s %u %u %u", cpu, &user, &nice, &system) < 0) {
		filebench_log(LOG_ERROR, "Cannot read /proc/stat");
		return (-1);
	}
	/* convert jiffies to nanosecs */
	return ((user+nice+system)*1000000);
}

#else /* HAVE_PROC_STAT */
vinteger_t
kstats_read_cpu(void)
{
	return (0);
}
#endif
#endif /* HAVE_LIBKSTAT */

/*
 * Returns the net cpu time used since the beginning of the run.
 * Just calls kstat_read_cpu() and subtracts stats_cputime which
 * is set at the beginning of the filebench run.
 */
static hrtime_t
kstats_read_cpu_relative(void)
{
	hrtime_t cputime;

	cputime = kstats_read_cpu();
	return (cputime - stats_cputime);
}

/*
 * IO Overhead CPU is the amount of CPU that is incurred running
 * the benchmark infrastructure.
 *
 * It is computed as the sum of micro-state cpu time for each
 * thread around the op being tested.
 *
 * Overhead time is computed for each flow.
 *
 * System overhead is computed as the overhead for I/O flows
 * plus all other time running non-io related flowops
 *
 */

/*
 * Computes and returns the overhead CPU time attibutable to
 * IO type flowops.
 */
static hrtime_t
io_stats_ohead(void)
{
	flowstat_t *iostat = &globalstats[FLOW_TYPE_IO];
	flowstat_t *aiostat = &globalstats[FLOW_TYPE_AIO];
	flowstat_t *glstat = &globalstats[FLOW_TYPE_GLOBAL];

	filebench_log(LOG_DEBUG_NEVER,
	    "Computing overhead as %lld + %lld - %lld - %lld",
	    glstat->fs_mstate[FLOW_MSTATE_OHEAD],
	    glstat->fs_mstate[FLOW_MSTATE_CPU],
	    iostat->fs_mstate[FLOW_MSTATE_CPU],
	    aiostat->fs_mstate[FLOW_MSTATE_CPU]);

	return ((glstat->fs_mstate[FLOW_MSTATE_OHEAD] +
	    glstat->fs_mstate[FLOW_MSTATE_CPU] -
	    iostat->fs_mstate[FLOW_MSTATE_CPU] -
	    aiostat->fs_mstate[FLOW_MSTATE_CPU]));
}

/*
 * Returns the total overhead CPU time.
 */
static hrtime_t
gl_stats_ohead(void)
{
	flowstat_t *glstat = &globalstats[FLOW_TYPE_GLOBAL];

	return (glstat->fs_mstate[FLOW_MSTATE_OHEAD]);
}

/*
 * Places the value represented by "name" into the var_integer field of the
 * supplied var_t. Compares the supplied "name" with a set of predefined
 * names and calculates the value from the appropriate globalstats field(s).
 */
var_t *
stats_findvar(var_t *var, char *name)
{
	flowstat_t *iostat = &globalstats[FLOW_TYPE_IO];
	flowstat_t *aiostat = &globalstats[FLOW_TYPE_AIO];
	flowstat_t *glstat = &globalstats[FLOW_TYPE_GLOBAL];

	filebench_log(LOG_DEBUG_IMPL, "reading stats %s", name);

	if (globalstats == NULL)
		globalstats = malloc(FLOW_TYPES * sizeof (flowstat_t));

	if (strcmp(name, "iocount") == 0) {
		var->var_integer = iostat->fs_count +
		    aiostat->fs_count;
		filebench_log(LOG_DEBUG_IMPL, "reading stats %s = %lld",
		    name, var->var_integer);
		return (var);
	}

	if (strcmp(name, "iorate") == 0) {
		/* LINTED E_ASSIGMENT_CAUSE_LOSS_PREC */
		var->var_integer = (iostat->fs_count + aiostat->fs_count) /
		    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS);
		return (var);
	}


	if (strcmp(name, "ioreadrate") == 0) {
		/* LINTED E_ASSIGMENT_CAUSE_LOSS_PREC */
		var->var_integer = (iostat->fs_rcount + aiostat->fs_rcount) /
		    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS);
		return (var);
	}


	if (strcmp(name, "iowriterate") == 0) {
		/* LINTED E_ASSIGMENT_CAUSE_LOSS_PREC */
		var->var_integer = (iostat->fs_wcount + aiostat->fs_wcount) /
		    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS);
		return (var);
	}


	if (strcmp(name, "iobandwidth") == 0) {
		/* LINTED E_ASSIGMENT_CAUSE_LOSS_PREC */
		var->var_integer =
		    ((iostat->fs_bytes + aiostat->fs_bytes) / (1024 * 1024)) /
		    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS);
		return (var);
	}

	if (strcmp(name, "iolatency") == 0) {
		var->var_integer = iostat->fs_count ?
		    iostat->fs_mstate[FLOW_MSTATE_LAT] /
		    (iostat->fs_count * 1000UL) : 0;
		return (var);
	}

	if (strcmp(name, "iocpu") == 0) {
		var->var_integer = (iostat->fs_count + aiostat->fs_count) ?
		    (iostat->fs_mstate[FLOW_MSTATE_CPU] +
		    aiostat->fs_mstate[FLOW_MSTATE_CPU]) / ((iostat->fs_count +
		    aiostat->fs_count) * 1000UL) : 0;
		return (var);
	}


	if (strcmp(name, "oheadcpu") == 0) {
		var->var_integer = (iostat->fs_count + aiostat->fs_count) ?
		    io_stats_ohead() / ((iostat->fs_count +
		    aiostat->fs_count) * 1000UL) : 0;
		return (var);
	}

	if (strcmp(name, "iowait") == 0) {
		var->var_integer = iostat->fs_count ?
		    iostat->fs_mstate[FLOW_MSTATE_WAIT] /
		    (iostat->fs_count * 1000UL) : 0;
		return (var);
	}

	if (strcmp(name, "syscpu") == 0) {
		/* LINTED E_ASSIGMENT_CAUSE_LOSS_PREC */
		var->var_integer = glstat->fs_syscpu / 1000.0;
		return (var);
	}

	if (strcmp(name, "iocpusys") == 0) {
		var->var_integer = (iostat->fs_count + aiostat->fs_count) ?
		    iostat->fs_syscpu / ((iostat->fs_count +
		    aiostat->fs_count) * 1000UL) : 0;

		return (var);
	}

	filebench_log(LOG_DEBUG_IMPL,
	    "error reading stats %s", name);

	return (NULL);
}

/*
 * Initializes the static variable "stats_cputime" with the
 * current cpu time, for use by kstats_read_cpu_relative.
 */
void
stats_init(void)
{
#if defined(HAVE_LIBKSTAT) || defined(LINUX_PORT)
	stats_cputime = kstats_read_cpu();
#else
	stats_cputime = 0;
#endif /* HAVE_LIBKSTAT */
}

/*
 * Add a flowstat b to a, leave sum in a.
 */
static void
stats_add(flowstat_t *a, flowstat_t *b)
{
	int i;

	a->fs_count += b->fs_count;
	a->fs_rcount += b->fs_rcount;
	a->fs_wcount += b->fs_wcount;
	a->fs_bytes += b->fs_bytes;
	a->fs_rbytes += b->fs_rbytes;
	a->fs_wbytes += b->fs_wbytes;

	for (i = 0; i < FLOW_MSTATES; i++)
		a->fs_mstate[i] += b->fs_mstate[i];
}

/*
 * Takes a "snapshot" of the global statistics. Actually, it calculates
 * them from the local statistics maintained by each flowop.
 * First the routine pauses filebench, then rolls the statistics for
 * each flowop into its associated FLOW_MASTER flowop.
 * Next all the FLOW_MASTER flowops' statistics are written
 * to the log file followed by the global totals. Then filebench
 * operation is allowed to resume.
 */
void
stats_snap(void)
{
	flowstat_t *iostat = &globalstats[FLOW_TYPE_IO];
	flowstat_t *aiostat = &globalstats[FLOW_TYPE_AIO];
	flowstat_t *glstat = &globalstats[FLOW_TYPE_GLOBAL];
	hrtime_t cputime;
	flowop_t *flowop;
	char *str;

	if (globalstats == NULL) {
		filebench_log(LOG_ERROR,
		    "'stats snap' called before 'stats clear'");
		return;
	}

	globalstats->fs_etime = gethrtime();

	filebench_log(LOG_DEBUG_SCRIPT, "Stats period = %ds",
	    (globalstats->fs_etime - globalstats->fs_stime) / 1000000000);

	/* Freeze statistics during update */
	filebench_shm->bequiet = 1;

	flowop = filebench_shm->flowoplist;
	while (flowop) {
		flowop_t *flowop_master;

		if (flowop->fo_instance == FLOW_MASTER) {
			flowop = flowop->fo_next;
			continue;
		}

		flowop_master = flowop_find_one(flowop->fo_name,
		    FLOW_MASTER);

		/* Roll up per-flowop into global stats */
		stats_add(&globalstats[flowop->fo_type],
		    &flowop->fo_stats);
		stats_add(&globalstats[FLOW_TYPE_GLOBAL],
		    &flowop->fo_stats);

		if (flowop_master && IS_FLOW_ACTIVE(flowop)) {
			flowop_master->fo_stats.fs_active++;
		}

		if (flowop_master) {
			/* Roll up per-flow stats into master */
			flowop_master->fo_stats.fs_children++;
			stats_add(&flowop_master->fo_stats, &flowop->fo_stats);
		} else {
			filebench_log(LOG_DEBUG_NEVER,
			    "flowop_stats could not find %s",
			    flowop->fo_name);
		}

		filebench_log(LOG_DEBUG_SCRIPT,
		    "flowop %-20s-%4d  - %5d ops, %5.1lf, ops/s %5.1lfmb/s "
		    "%8.3fms/op",
		    flowop->fo_name,
		    flowop->fo_instance,
		    flowop->fo_stats.fs_count,
		    flowop->fo_stats.fs_count /
		    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS),
		    (flowop->fo_stats.fs_bytes / (1024 * 1024)) /
		    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS),
		    flowop->fo_stats.fs_count ?
		    flowop->fo_stats.fs_mstate[FLOW_MSTATE_LAT] /
		    (flowop->fo_stats.fs_count * 1000000.0) : 0);

		flowop = flowop->fo_next;

	}

#if defined(HAVE_LIBKSTAT) || defined(LINUX_PORT)
	cputime = kstats_read_cpu_relative();
#endif /* HAVE_LIBKSTAT */

	filebench_log(LOG_DEBUG_IMPL,
	    "cputime = %lld, ohead = %lld",
	    cputime / 1000000000,
	    io_stats_ohead() / 1000000000);
	iostat->fs_syscpu =
	    (cputime > io_stats_ohead()) ?
	    (cputime - io_stats_ohead()) : 0;
	glstat->fs_syscpu =
	    (cputime > gl_stats_ohead()) ?
	    (cputime - gl_stats_ohead()) : 0;


	flowop = filebench_shm->flowoplist;
	str = malloc(1048576);
	*str = NULL;
	(void) strcpy(str, "Per-Operation Breakdown\n");
	while (flowop) {
		char line[1024];

		if (flowop->fo_instance != FLOW_MASTER) {
			flowop = flowop->fo_next;
			continue;
		}

		(void) snprintf(line, sizeof (line), "%-20s %8.0lfops/s "
		    "%5.1lfmb/s %8.1fms/op %8.0fus/op-cpu\n",
		    flowop->fo_name,
		    flowop->fo_stats.fs_count /
		    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS),
		    (flowop->fo_stats.fs_bytes / (1024 * 1024)) /
		    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS),
		    flowop->fo_stats.fs_count ?
		    flowop->fo_stats.fs_mstate[FLOW_MSTATE_LAT] /
		    (flowop->fo_stats.fs_count * 1000000.0) : 0,
		    flowop->fo_stats.fs_count ?
		    flowop->fo_stats.fs_mstate[FLOW_MSTATE_CPU] /
		    (flowop->fo_stats.fs_count * 1000.0) : 0);
		(void) strcat(str, line);

		flowop = flowop->fo_next;
	}

	filebench_log(LOG_INFO, "%s", str);
	free(str);

	filebench_log(LOG_INFO,
	    "\nIO Summary:      %5d ops %5.1lf ops/s, (%0.0lf/%0.0lf r/w) "
	    "%5.1lfmb/s, %6.0fus cpu/op, %5.1fms latency",
	    iostat->fs_count + aiostat->fs_count,
	    (iostat->fs_count + aiostat->fs_count) /
	    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS),
	    (iostat->fs_rcount + aiostat->fs_rcount) /
	    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS),
	    (iostat->fs_wcount + aiostat->fs_wcount) /
	    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS),
	    ((iostat->fs_bytes + aiostat->fs_bytes) / (1024 * 1024)) /
	    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS),
	    (iostat->fs_rcount + iostat->fs_wcount +
	    aiostat->fs_rcount + aiostat->fs_wcount) ?
	    (iostat->fs_syscpu / 1000.0) /
	    (iostat->fs_rcount + iostat->fs_wcount +
	    aiostat->fs_rcount + aiostat->fs_wcount) : 0,
	    (iostat->fs_rcount + iostat->fs_wcount) ?
	    iostat->fs_mstate[FLOW_MSTATE_LAT] /
	    ((iostat->fs_rcount + iostat->fs_wcount) * 1000000.0) : 0);


	filebench_shm->bequiet = 0;
}

/*
 * Dumps the per-operation statistics and global statistics to the dump file.
 */
void
stats_dump(char *filename)
{
	flowstat_t *iostat = &globalstats[FLOW_TYPE_IO];
	flowstat_t *aiostat = &globalstats[FLOW_TYPE_AIO];
	flowop_t *flowop;

	(void) strcpy(filebench_shm->dump_filename, filename);

	filebench_log(LOG_INFO, "in statsdump %s", filename);

	if (filebench_shm->dump_fd > 0) {
		(void) close(filebench_shm->dump_fd);
		filebench_shm->dump_fd = -1;
	}

	filebench_log(LOG_DUMP, "Flowop totals:");

	flowop = filebench_shm->flowoplist;
	while (flowop) {

		if (flowop->fo_instance != FLOW_MASTER) {
			flowop = flowop->fo_next;
			continue;
		}

		filebench_log(LOG_DUMP,
		    "%-20s %8.0lfops/s %5.1lfmb/s "
		    "%8.1fms/op %8.0fus/op-cpu",
		    flowop->fo_name,
		    flowop->fo_stats.fs_count /
		    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS),
		    (flowop->fo_stats.fs_bytes / (1024 * 1024)) /
		    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS),
		    flowop->fo_stats.fs_count ?
		    flowop->fo_stats.fs_mstate[FLOW_MSTATE_LAT] /
		    (flowop->fo_stats.fs_count * 1000000.0) : 0,
		    flowop->fo_stats.fs_count ?
		    flowop->fo_stats.fs_mstate[FLOW_MSTATE_CPU] /
		    (flowop->fo_stats.fs_count * 1000.0) : 0);

		flowop = flowop->fo_next;
	}

	filebench_log(LOG_DUMP, "");
	filebench_log(LOG_DUMP,
	    "IO Summary:      %8d ops %8.1lf ops/s, %8.0lf/%0.0lf r/w"
	    "%8.1lfmb/s, %8.0fuscpu/op",

	    iostat->fs_count + aiostat->fs_count,
	    (iostat->fs_count + aiostat->fs_count) /
	    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS),

	    (iostat->fs_rcount + aiostat->fs_rcount) /
	    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS),

	    (iostat->fs_wcount + aiostat->fs_wcount) /
	    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS),

	    ((iostat->fs_bytes + aiostat->fs_bytes) / (1024 * 1024)) /
	    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS),

	    (iostat->fs_rcount + iostat->fs_wcount +
	    aiostat->fs_rcount + aiostat->fs_wcount) ?
	    (iostat->fs_syscpu / 1000.0) /
	    (iostat->fs_rcount + iostat->fs_wcount +
	    aiostat->fs_rcount + aiostat->fs_wcount) : 0);
}

/*
 * Same as stats_dump, but in xml format.
 */
void
stats_xmldump(char *filename)
{
	flowstat_t *iostat = &globalstats[FLOW_TYPE_IO];
	flowstat_t *aiostat = &globalstats[FLOW_TYPE_AIO];
	flowop_t *flowop;

	(void) strcpy(filebench_shm->dump_filename, filename);

	if (filebench_shm->dump_fd > 0) {
		(void) close(filebench_shm->dump_fd);
		filebench_shm->dump_fd = -1;
	}

	filebench_log(LOG_DUMP, "<stat_doc name=\"Filebench Workload\">");
	filebench_log(LOG_DUMP, "<stat_group name=\"Flowop totals\">");
	filebench_log(LOG_DUMP, "<cell_list>");

	flowop = filebench_shm->flowoplist;
	while (flowop) {
		if (flowop->fo_instance != FLOW_MASTER) {
			flowop = flowop->fo_next;
			continue;
		}

		filebench_log(LOG_DUMP, "<cell>%0.0lf</cell>",
		    flowop->fo_stats.fs_count /
		    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS));
		filebench_log(LOG_DUMP, "<cell>%0.1lf</cell>",
		    (flowop->fo_stats.fs_bytes / (1024 * 1024)) /
		    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS));
		filebench_log(LOG_DUMP, "<cell>%0.1lf</cell>",
		    flowop->fo_stats.fs_count ?
		    flowop->fo_stats.fs_mstate[FLOW_MSTATE_LAT] /
		    (flowop->fo_stats.fs_count * 1000000.0) : 0);
		filebench_log(LOG_DUMP, "<cell>%0.0lf</cell>",
		    flowop->fo_stats.fs_count ?
		    flowop->fo_stats.fs_mstate[FLOW_MSTATE_CPU] /
		    (flowop->fo_stats.fs_count * 1000.0) : 0);

		flowop = flowop->fo_next;
	}
	filebench_log(LOG_DUMP, "</cell_list>");

	filebench_log(LOG_DUMP, "<dim_list>");
	filebench_log(LOG_DUMP, "<dim>");
	filebench_log(LOG_DUMP, "<dimval>Operations/sec</dimval>");
	filebench_log(LOG_DUMP, "<dimval>MB/sec</dimval>");
	filebench_log(LOG_DUMP, "<dimval>Latency (ms per operation)</dimval>");
	filebench_log(LOG_DUMP, "<dimval>CPU (us per operation)</dimval>");
	filebench_log(LOG_DUMP, "</dim>");

	filebench_log(LOG_DUMP, "<dim>");
	flowop = filebench_shm->flowoplist;
	while (flowop) {
		if (flowop->fo_instance != FLOW_MASTER) {
			flowop = flowop->fo_next;
			continue;
		}
		filebench_log(LOG_DUMP, "<dimval>%s</dimval>", flowop->fo_name);
		flowop = flowop->fo_next;
	}
	filebench_log(LOG_DUMP, "</dim>");
	filebench_log(LOG_DUMP, "</dim_list>");
	filebench_log(LOG_DUMP, "</stat_group>");

	filebench_log(LOG_DUMP, "<stat_group name=\"IO Summary\">");
	filebench_log(LOG_DUMP, "<cell_list>");
	filebench_log(LOG_DUMP, "<cell>%0d</cell>",
	    iostat->fs_count + aiostat->fs_count);
	filebench_log(LOG_DUMP, "<cell>%0.1lf</cell>",
	    (iostat->fs_count + aiostat->fs_count) /
	    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS));
	filebench_log(LOG_DUMP, "<cell>%0.0lf</cell>",
	    (iostat->fs_rcount + aiostat->fs_rcount) /
	    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS));
	filebench_log(LOG_DUMP, "<cell>%0.0lf</cell>",
	    (iostat->fs_wcount + aiostat->fs_wcount) /
	    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS));
	filebench_log(LOG_DUMP, "<cell>%0.1lf</cell>",
	    ((iostat->fs_bytes + aiostat->fs_bytes) / (1024 * 1024)) /
	    ((globalstats->fs_etime - globalstats->fs_stime) / FSECS));
	filebench_log(LOG_DUMP, "<cell>%0.0f</cell>",
	    (iostat->fs_rcount + iostat->fs_wcount + aiostat->fs_rcount +
	    aiostat->fs_wcount) ? (iostat->fs_syscpu / 1000.0) /
	    (iostat->fs_rcount + iostat->fs_wcount + aiostat->fs_rcount +
	    aiostat->fs_wcount) : 0);
	filebench_log(LOG_DUMP, "</cell_list>");

	filebench_log(LOG_DUMP, "<dim_list>");
	filebench_log(LOG_DUMP, "<dim>");
	filebench_log(LOG_DUMP, "<dimval>Operations</dimval>");
	filebench_log(LOG_DUMP, "<dimval>Operations/sec</dimval>");
	filebench_log(LOG_DUMP, "<dimval>Reads</dimval>");
	filebench_log(LOG_DUMP, "<dimval>Writes</dimval>");
	filebench_log(LOG_DUMP, "<dimval>MB/sec</dimval>");
	filebench_log(LOG_DUMP, "<dimval>CPU (us per operation)</dimval>");
	filebench_log(LOG_DUMP, "</dim>");

	filebench_log(LOG_DUMP, "<dim>");
	filebench_log(LOG_DUMP, "<dimval>IO Summary</dimval>");
	filebench_log(LOG_DUMP, "</dim>");
	filebench_log(LOG_DUMP, "</dim_list>");
	filebench_log(LOG_DUMP, "</stat_group>");
	filebench_log(LOG_DUMP, "</stat_doc>");
}

/*
 * Clears all the statistics variables (fo_stats) for every defined flowop.
 * It also creates a global flowstat table if one doesn't already exist and
 * clears it.
 */
void
stats_clear(void)
{
	flowop_t *flowop;

#ifdef HAVE_LIBKSTAT
	stats_cputime = kstats_read_cpu();
#else
	stats_cputime = 0;
#endif /* HAVE_LIBKSTAT */

	if (globalstats == NULL)
		globalstats = malloc(FLOW_TYPES * sizeof (flowstat_t));

	(void) memset(globalstats, 0, FLOW_TYPES * sizeof (flowstat_t));

	flowop = filebench_shm->flowoplist;

	while (flowop) {
		filebench_log(LOG_DEBUG_IMPL, "Clearing stats for %s-%d",
		    flowop->fo_name,
		    flowop->fo_instance);
		(void) memset(&flowop->fo_stats, 0, sizeof (flowstat_t));
		flowop = flowop->fo_next;
	}

	(void) memset(globalstats, 0, sizeof (flowstat_t));
	globalstats->fs_stime = gethrtime();
}
