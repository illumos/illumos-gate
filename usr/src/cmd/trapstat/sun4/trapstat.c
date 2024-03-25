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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <strings.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/pset.h>
#include <sys/varargs.h>
#include <sys/trapstat.h>
#include <sys/wait.h>
#include <stddef.h>
#include <termio.h>
#include "_trapstat.h"

#define	TSTAT_DEVICE	"/dev/trapstat"
#define	TSTAT_COMMAND	"trapstat"
#define	TSTAT_DELTA(data, old, member) g_absolute ? (data)->member : \
	(uint64_t)(0.5 + (g_interval / (double)((data)->tdata_snapts - \
	(old)->tdata_snapts)) * (double)((data)->member - (old)->member))

#define	TSTAT_PRINT_MISSDATA(diff, time) \
	(void) printf(" %9lld %4.1f", (diff), (time));

#define	TSTAT_PAGESIZE_MODIFIERS	" kmgtp"
#define	TSTAT_PAGESIZE_STRLEN		10
#define	TSTAT_MAX_RATE			5000
#define	TSTAT_COLUMN_OFFS	26
#define	TSTAT_COLUMNS_PER_CPU	9

static tstat_data_t *g_data[2];
static tstat_data_t *g_ndata, *g_odata;
static processorid_t g_max_cpus;
static int8_t *g_selected;
static timer_t g_tid;
static int g_interval = NANOSEC;
static int g_peffect = 1;
static int g_absolute = 0;
static sigset_t g_oset;

static psetid_t g_pset = PS_NONE;
static processorid_t *g_pset_cpus;
static uint_t g_pset_ncpus;

static int g_cpus_per_line = (80 - TSTAT_COLUMN_OFFS) / TSTAT_COLUMNS_PER_CPU;
static int g_winch;

static int g_pgsizes;
static size_t *g_pgsize;
static char **g_pgnames;
static size_t g_datasize;

static int g_gen;
static int g_fd;
static uint8_t g_active[TSTAT_NENT];

static hrtime_t g_start;

static int g_exec_errno;
static int g_child_exited;
static int g_child_status;

static void (*g_process)(void *, uint64_t, double);
static void *g_arg;

typedef struct tstat_sum {
	uint64_t	tsum_diff;
	double		tsum_time;
} tstat_sum_t;

/*
 * Define a dummy g_traps reader to establish a symbol capabilities lead.
 * This routine should never be called, as the sun4u and sun4v variants
 * will be used as appropriate.
 */
/* ARGSUSED0 */
tstat_ent_t *
get_trap_ent(int ndx)
{
	return (NULL);
}

static void
usage(void)
{
	(void) fprintf(stderr,
	    "\nusage:  trapstat [ -t | -T | -e entrylist ]\n"
	    "   [ -C psrset | -c cpulist ]\n"
	    "   [ -P ] [ -a ] [ -r rate ] [[ interval [ count ] ] | "
	    "command [ args ] ]\n\n"
	    "Trap selection options:\n\n"
	    " -t             TLB statistics\n"
	    " -T             TLB statistics, with pagesize information\n"
	    " -e entrylist   Enable statistics only for entries specified "
	    "by entrylist\n\n"
	    "CPU selection options:\n\n"
	    " -c cpulist     Enable statistics only for specified CPU list\n"
	    " -C psrset      Enable statistics only for specified processor "
	    "set\n\n"
	    "Other options:\n\n"
	    " -a             Display trap values as accumulating values "
	    "instead of rates\n"
	    " -l             List trap table entries and exit\n"
	    " -P             Display output in parsable format\n"
	    " -r hz          Set sampling rate to be hz samples "
	    "per second\n\n");

	exit(EXIT_FAILURE);
}

static void
fatal(char *fmt, ...)
{
	va_list ap;
	int error = errno;

	va_start(ap, fmt);

	(void) fprintf(stderr, TSTAT_COMMAND ": ");
	(void) vfprintf(stderr, fmt, ap);

	if (fmt[strlen(fmt) - 1] != '\n')
		(void) fprintf(stderr, ": %s\n", strerror(error));

	exit(EXIT_FAILURE);
}

static void
set_width(void)
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

	g_cpus_per_line = (win.ws_col - TSTAT_COLUMN_OFFS) /
	    TSTAT_COLUMNS_PER_CPU;

	if (g_cpus_per_line < 1)
		g_cpus_per_line = 1;
}

static void
intr(int signo)
{
	int error = errno;

	switch (signo) {
	case SIGWINCH:
		g_winch = 1;
		set_width();
		break;

	case SIGCHLD:
		g_child_exited = 1;

		while (wait(&g_child_status) == -1 && errno == EINTR)
			continue;
		break;

	default:
		break;
	}

	errno = error;
}

static void
setup(void)
{
	struct sigaction act;
	struct sigevent ev;
	sigset_t set;
	int i;

	for (i = 0; i < TSTAT_NENT; i++) {
		tstat_ent_t	*gtp;

		if ((gtp = get_trap_ent(i)) == NULL)
			continue;

		if (gtp->tent_type == TSTAT_ENT_RESERVED)
			gtp->tent_name = "reserved";

		if (gtp->tent_type == TSTAT_ENT_UNUSED)
			gtp->tent_name = "unused";
	}

	g_max_cpus = (processorid_t)sysconf(_SC_CPUID_MAX) + 1;

	if ((g_selected = malloc(sizeof (int8_t) * g_max_cpus)) == NULL)
		fatal("could not allocate g_selected");

	bzero(g_selected, sizeof (int8_t) * g_max_cpus);

	g_pset_cpus = malloc(sizeof (processorid_t) * g_max_cpus);
	if (g_pset_cpus == NULL)
		fatal("could not allocate g_pset_cpus");

	bzero(g_pset_cpus, sizeof (processorid_t) * g_max_cpus);

	if ((g_pgsizes = getpagesizes(NULL, 0)) == -1)
		fatal("getpagesizes()");

	if ((g_pgsize = malloc(sizeof (size_t) * g_pgsizes)) == NULL)
		fatal("could not allocate g_pgsize array");

	if (getpagesizes(g_pgsize, g_pgsizes) == -1)
		fatal("getpagesizes(%d)", g_pgsizes);

	if ((g_pgnames = malloc(sizeof (char *) * g_pgsizes)) == NULL)
		fatal("could not allocate g_pgnames");

	for (i = 0; i < g_pgsizes; i++) {
		size_t j, mul;
		size_t sz = g_pgsize[i];

		if ((g_pgnames[i] = malloc(TSTAT_PAGESIZE_STRLEN)) == NULL)
			fatal("could not allocate g_pgnames[%d]", i);

		for (j = 0, mul = 10; (1 << mul) <= sz; j++, mul += 10)
			continue;

		(void) snprintf(g_pgnames[i], TSTAT_PAGESIZE_STRLEN,
		    "%d%c", sz >> (mul - 10), " kmgtpe"[j]);
	}

	g_datasize =
	    sizeof (tstat_data_t) + (g_pgsizes - 1) * sizeof (tstat_pgszdata_t);

	if ((g_data[0] = malloc(g_datasize * g_max_cpus)) == NULL)
		fatal("could not allocate data buffer 0");

	if ((g_data[1] = malloc(g_datasize * g_max_cpus)) == NULL)
		fatal("could not allocate data buffer 1");

	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = intr;
	(void) sigaction(SIGUSR1, &act, NULL);
	(void) sigaction(SIGCHLD, &act, NULL);

	(void) sigaddset(&act.sa_mask, SIGCHLD);
	(void) sigaddset(&act.sa_mask, SIGUSR1);
	(void) sigaction(SIGWINCH, &act, NULL);
	set_width();

	(void) sigemptyset(&set);
	(void) sigaddset(&set, SIGCHLD);
	(void) sigaddset(&set, SIGUSR1);
	(void) sigaddset(&set, SIGWINCH);
	(void) sigprocmask(SIG_BLOCK, &set, &g_oset);

	ev.sigev_notify = SIGEV_SIGNAL;
	ev.sigev_signo = SIGUSR1;

	if (timer_create(CLOCK_HIGHRES, &ev, &g_tid) == -1)
		fatal("cannot create CLOCK_HIGHRES timer");
}

static void
set_interval(hrtime_t nsec)
{
	struct itimerspec ts;

	/*
	 * If the interval is less than one second, we'll report the
	 * numbers in terms of rate-per-interval.  If the interval is
	 * greater than one second, we'll report numbers in terms of
	 * rate-per-second.
	 */
	g_interval = nsec < NANOSEC ? nsec : NANOSEC;

	ts.it_value.tv_sec = nsec / NANOSEC;
	ts.it_value.tv_nsec = nsec % NANOSEC;
	ts.it_interval.tv_sec = nsec / NANOSEC;
	ts.it_interval.tv_nsec = nsec % NANOSEC;

	if (timer_settime(g_tid, TIMER_RELTIME, &ts, NULL) == -1)
		fatal("cannot set time on CLOCK_HIGHRES timer");
}

static void
print_entries(FILE *stream, int parsable)
{
	int entno;

	if (!parsable) {
		(void) fprintf(stream, "  %3s %3s | %-20s | %s\n", "hex",
		    "dec", "entry name", "description");

		(void) fprintf(stream, "----------+----------------------"
		    "+-----------------------\n");
	}

	for (entno = 0; entno < TSTAT_NENT; entno++) {
		tstat_ent_t	*gtp;

		if ((gtp = get_trap_ent(entno)) == NULL)
			continue;

		if (gtp->tent_type != TSTAT_ENT_USED)
			continue;

		(void) fprintf(stream, "0x%03x %3d %s%-20s %s%s\n",
		    entno, entno,
		    parsable ? "" : "| ", gtp->tent_name,
		    parsable ? "" : "| ", gtp->tent_descr);
	}
}

static void
select_entry(char *entry)
{
	ulong_t entno;
	char *end;

	/*
	 * The entry may be specified as a number (e.g., "0x68", "104") or
	 * as a name ("dtlb-miss").
	 */
	entno = strtoul(entry, &end, 0);

	if (*end == '\0') {
		if (entno >= TSTAT_NENT)
			goto bad_entry;
	} else {
		for (entno = 0; entno < TSTAT_NENT; entno++) {
			tstat_ent_t	*gtp;

			if ((gtp = get_trap_ent(entno)) == NULL)
				continue;

			if (gtp->tent_type != TSTAT_ENT_USED)
				continue;

			if (strcmp(entry, gtp->tent_name) == 0)
				break;
		}

		if (entno == TSTAT_NENT)
			goto bad_entry;
	}

	if (ioctl(g_fd, TSTATIOC_ENTRY, entno) == -1)
		fatal("TSTATIOC_ENTRY failed for entry 0x%x", entno);

	g_active[entno] = 1;
	return;

bad_entry:
	(void) fprintf(stderr, TSTAT_COMMAND ": invalid entry '%s'", entry);
	(void) fprintf(stderr, "; valid entries:\n\n");
	print_entries(stderr, 0);
	exit(EXIT_FAILURE);
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

	g_selected[cpu] = 1;
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
			g_selected[low] = 1;
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
		if (g_selected[i])
			break;

	if (i != g_max_cpus)
		fatal("cannot specify both a processor and a processor set\n");

	g_pset = pset;
	g_pset_ncpus = g_max_cpus;

	if (pset_info(g_pset, NULL, &g_pset_ncpus, g_pset_cpus) == -1)
		fatal("invalid processor set: %d\n", g_pset);

	if (g_pset_ncpus == 0)
		fatal("processor set %d empty\n", g_pset);

	if (ioctl(g_fd, TSTATIOC_NOCPU) == -1)
		fatal("TSTATIOC_NOCPU failed");

	for (i = 0; i < g_pset_ncpus; i++)
		g_selected[g_pset_cpus[i]] = 1;
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
			if (!g_selected[g_pset_cpus[i]])
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
	 * to zero out the selection array.
	 */
	bzero(g_selected, sizeof (int8_t) * g_max_cpus);

	g_pset_ncpus = ncpus;

	if (ioctl(g_fd, TSTATIOC_STOP) == -1)
		fatal("TSTATIOC_STOP failed");

	if (ioctl(g_fd, TSTATIOC_NOCPU) == -1)
		fatal("TSATIOC_NOCPU failed");

	for (i = 0; i < g_pset_ncpus; i++) {
		g_selected[g_pset_cpus[i]] = 1;
		if (ioctl(g_fd, TSTATIOC_CPU, g_pset_cpus[i]) == -1)
			fatal("TSTATIOC_CPU failed for cpu %d", i);
	}

	/*
	 * Now that we have selected the CPUs, we're going to reenable
	 * trapstat, and reread the data for the current generation.
	 */
	if (ioctl(g_fd, TSTATIOC_GO) == -1)
		fatal("TSTATIOC_GO failed");

	if (ioctl(g_fd, TSTATIOC_READ, g_data[g_gen]) == -1)
		fatal("TSTATIOC_READ failed");
}

static void
missdata(tstat_missdata_t *miss, tstat_missdata_t *omiss)
{
	hrtime_t ts = g_ndata->tdata_snapts - g_odata->tdata_snapts;
	hrtime_t tick = g_ndata->tdata_snaptick - g_odata->tdata_snaptick;
	uint64_t raw = miss->tmiss_count - omiss->tmiss_count;
	uint64_t diff = g_absolute ? miss->tmiss_count :
	    (uint64_t)(0.5 + g_interval /
	    (double)ts * (double)(miss->tmiss_count - omiss->tmiss_count));
	hrtime_t peffect = raw * g_ndata->tdata_peffect * g_peffect, time;
	double p;

	/*
	 * Now we need to account for the trapstat probe effect.  Take
	 * the amount of time spent in the handler, and add the
	 * amount of time known to be due to the trapstat probe effect.
	 */
	time = miss->tmiss_time - omiss->tmiss_time + peffect;

	if (time >= tick) {
		/*
		 * This really shouldn't happen unless our calculation of
		 * the probe effect was vastly incorrect.  In any case,
		 * print 99.9 for the time instead of printing negative
		 * values...
		 */
		time = tick / 1000 * 999;
	}

	p = (double)time / (double)tick * (double)100.0;

	(*g_process)(g_arg, diff, p);
}

static void
tlbdata(tstat_tlbdata_t *tlb, tstat_tlbdata_t *otlb)
{
	missdata(&tlb->ttlb_tlb, &otlb->ttlb_tlb);
	missdata(&tlb->ttlb_tsb, &otlb->ttlb_tsb);
}

static void
print_missdata(double *ttl, uint64_t diff, double p)
{
	TSTAT_PRINT_MISSDATA(diff, p);

	if (ttl != NULL)
		*ttl += p;
}

static void
print_modepgsz(char *prefix, tstat_modedata_t *data, tstat_modedata_t *odata)
{
	int ps;
	size_t incr = sizeof (tstat_pgszdata_t);

	for (ps = 0; ps < g_pgsizes; ps++) {
		double ttl = 0.0;

		g_process = (void(*)(void *, uint64_t, double))print_missdata;
		g_arg = &ttl;

		(void) printf("%s %4s|", prefix, g_pgnames[ps]);
		tlbdata(&data->tmode_itlb, &odata->tmode_itlb);
		(void) printf(" |");
		tlbdata(&data->tmode_dtlb, &odata->tmode_dtlb);

		(void) printf(" |%4.1f\n", ttl);

		data = (tstat_modedata_t *)((uintptr_t)data + incr);
		odata = (tstat_modedata_t *)((uintptr_t)odata + incr);
	}
}

static void
parsable_modepgsz(char *prefix, tstat_modedata_t *data, tstat_modedata_t *odata)
{
	int ps;
	size_t incr = sizeof (tstat_pgszdata_t);

	g_process = (void(*)(void *, uint64_t, double))print_missdata;
	g_arg = NULL;

	for (ps = 0; ps < g_pgsizes; ps++) {
		(void) printf("%s %7d", prefix, g_pgsize[ps]);
		tlbdata(&data->tmode_itlb, &odata->tmode_itlb);
		tlbdata(&data->tmode_dtlb, &odata->tmode_dtlb);
		(void) printf("\n");

		data = (tstat_modedata_t *)((uintptr_t)data + incr);
		odata = (tstat_modedata_t *)((uintptr_t)odata + incr);
	}
}

static void
sum_missdata(void *sump, uint64_t diff, double p)
{
	tstat_sum_t *sum = *((tstat_sum_t **)sump);

	sum->tsum_diff += diff;
	sum->tsum_time += p;

	(*(tstat_sum_t **)sump)++;
}

static void
sum_modedata(tstat_modedata_t *data, tstat_modedata_t *odata, tstat_sum_t *sum)
{
	int ps, incr = sizeof (tstat_pgszdata_t);
	tstat_sum_t *sump;

	for (ps = 0; ps < g_pgsizes; ps++) {
		sump = sum;

		g_process = sum_missdata;
		g_arg = &sump;

		tlbdata(&data->tmode_itlb, &odata->tmode_itlb);
		tlbdata(&data->tmode_dtlb, &odata->tmode_dtlb);

		data = (tstat_modedata_t *)((uintptr_t)data + incr);
		odata = (tstat_modedata_t *)((uintptr_t)odata + incr);
	}
}

static void
print_sum(tstat_sum_t *sum, int divisor)
{
	int i;
	double ttl = 0.0;

	for (i = 0; i < 4; i++) {
		if (i == 2)
			(void) printf(" |");

		sum[i].tsum_time /= divisor;

		TSTAT_PRINT_MISSDATA(sum[i].tsum_diff, sum[i].tsum_time);
		ttl += sum[i].tsum_time;
	}

	(void) printf(" |%4.1f\n", ttl);
}

static void
print_tlbpgsz(tstat_data_t *data, tstat_data_t *odata)
{
	int i, cpu, ncpus = 0;
	char pre[12];
	tstat_sum_t sum[4];

	(void) printf("cpu m size| %9s %4s %9s %4s | %9s %4s %9s %4s |%4s\n"
	    "----------+-------------------------------+-----------------------"
	    "--------+----\n", "itlb-miss", "%tim", "itsb-miss", "%tim",
	    "dtlb-miss", "%tim", "dtsb-miss", "%tim", "%tim");

	bzero(sum, sizeof (sum));

	for (i = 0; i < g_max_cpus; i++) {
		tstat_pgszdata_t *pgsz = data->tdata_pgsz;
		tstat_pgszdata_t *opgsz = odata->tdata_pgsz;

		if ((cpu = data->tdata_cpuid) == -1)
			break;

		if (i != 0)
			(void) printf("----------+-----------------------------"
			    "--+-------------------------------+----\n");

		g_ndata = data;
		g_odata = odata;

		(void) sprintf(pre, "%3d u", cpu);
		print_modepgsz(pre, &pgsz->tpgsz_user, &opgsz->tpgsz_user);
		sum_modedata(&pgsz->tpgsz_user, &opgsz->tpgsz_user, sum);

		(void) printf("- - - - - + - - - - - - - - - - - - - -"
		    " - + - - - - - - - - - - - - - - - + - -\n");

		(void) sprintf(pre, "%3d k", cpu);
		print_modepgsz(pre, &pgsz->tpgsz_kernel, &opgsz->tpgsz_kernel);
		sum_modedata(&pgsz->tpgsz_kernel, &opgsz->tpgsz_kernel, sum);

		data = (tstat_data_t *)((uintptr_t)data + g_datasize);
		odata = (tstat_data_t *)((uintptr_t)odata + g_datasize);
		ncpus++;
	}

	(void) printf("==========+===============================+========="
	    "======================+====\n");
	(void) printf("      ttl |");
	print_sum(sum, ncpus);
	(void) printf("\n");
}

static void
parsable_tlbpgsz(tstat_data_t *data, tstat_data_t *odata)
{
	int i, cpu;
	char pre[30];

	for (i = 0; i < g_max_cpus; i++) {
		tstat_pgszdata_t *pgsz = data->tdata_pgsz;
		tstat_pgszdata_t *opgsz = odata->tdata_pgsz;

		if ((cpu = data->tdata_cpuid) == -1)
			break;

		g_ndata = data;
		g_odata = odata;

		(void) sprintf(pre, "%lld %3d u",
		    data->tdata_snapts - g_start, cpu);
		parsable_modepgsz(pre, &pgsz->tpgsz_user, &opgsz->tpgsz_user);

		pre[strlen(pre) - 1] = 'k';
		parsable_modepgsz(pre, &pgsz->tpgsz_kernel,
		    &opgsz->tpgsz_kernel);

		data = (tstat_data_t *)((uintptr_t)data + g_datasize);
		odata = (tstat_data_t *)((uintptr_t)odata + g_datasize);
	}
}

static void
print_modedata(tstat_modedata_t *data, tstat_modedata_t *odata, int parsable)
{
	int ps, i;
	size_t incr = sizeof (tstat_pgszdata_t);
	tstat_sum_t sum[4], *sump = sum;
	double ttl = 0.0;

	bzero(sum, sizeof (sum));
	g_process = sum_missdata;
	g_arg = &sump;

	for (ps = 0; ps < g_pgsizes; ps++) {
		tlbdata(&data->tmode_itlb, &odata->tmode_itlb);
		tlbdata(&data->tmode_dtlb, &odata->tmode_dtlb);

		data = (tstat_modedata_t *)((uintptr_t)data + incr);
		odata = (tstat_modedata_t *)((uintptr_t)odata + incr);
		sump = sum;
	}

	for (i = 0; i < 4; i++) {
		if (i == 2 && !parsable)
			(void) printf(" |");

		TSTAT_PRINT_MISSDATA(sum[i].tsum_diff, sum[i].tsum_time);
		ttl += sum[i].tsum_time;
	}

	if (parsable) {
		(void) printf("\n");
		return;
	}

	(void) printf(" |%4.1f\n", ttl);
}

static void
print_tlb(tstat_data_t *data, tstat_data_t *odata)
{
	int i, cpu, ncpus = 0;
	tstat_sum_t sum[4];

	(void) printf("cpu m| %9s %4s %9s %4s | %9s %4s %9s %4s |%4s\n"
	    "-----+-------------------------------+-----------------------"
	    "--------+----\n", "itlb-miss", "%tim", "itsb-miss", "%tim",
	    "dtlb-miss", "%tim", "dtsb-miss", "%tim", "%tim");

	bzero(sum, sizeof (sum));

	for (i = 0; i < g_max_cpus; i++) {
		tstat_pgszdata_t *pgsz = data->tdata_pgsz;
		tstat_pgszdata_t *opgsz = odata->tdata_pgsz;

		if ((cpu = data->tdata_cpuid) == -1)
			break;

		if (i != 0)
			(void) printf("-----+-------------------------------+-"
			    "------------------------------+----\n");

		g_ndata = data;
		g_odata = odata;

		(void) printf("%3d u|", cpu);
		print_modedata(&pgsz->tpgsz_user, &opgsz->tpgsz_user, 0);
		sum_modedata(&pgsz->tpgsz_user, &opgsz->tpgsz_user, sum);

		(void) printf("%3d k|", cpu);
		print_modedata(&pgsz->tpgsz_kernel, &opgsz->tpgsz_kernel, 0);
		sum_modedata(&pgsz->tpgsz_kernel, &opgsz->tpgsz_kernel, sum);

		data = (tstat_data_t *)((uintptr_t)data + g_datasize);
		odata = (tstat_data_t *)((uintptr_t)odata + g_datasize);
		ncpus++;
	}

	(void) printf("=====+===============================+========="
	    "======================+====\n");

	(void) printf(" ttl |");
	print_sum(sum, ncpus);
	(void) printf("\n");
}

static void
parsable_tlb(tstat_data_t *data, tstat_data_t *odata)
{
	int i, cpu;

	for (i = 0; i < g_max_cpus; i++) {
		tstat_pgszdata_t *pgsz = data->tdata_pgsz;
		tstat_pgszdata_t *opgsz = odata->tdata_pgsz;

		if ((cpu = data->tdata_cpuid) == -1)
			break;

		g_ndata = data;
		g_odata = odata;

		(void) printf("%lld %3d u ", data->tdata_snapts - g_start, cpu);
		print_modedata(&pgsz->tpgsz_user, &opgsz->tpgsz_user, 1);
		(void) printf("%lld %3d k ", data->tdata_snapts - g_start, cpu);
		print_modedata(&pgsz->tpgsz_kernel, &opgsz->tpgsz_kernel, 1);

		data = (tstat_data_t *)((uintptr_t)data + g_datasize);
		odata = (tstat_data_t *)((uintptr_t)odata + g_datasize);
	}
}

static void
print_stats(tstat_data_t *data, tstat_data_t *odata)
{
	int i, j, k, done;
	processorid_t id;
	tstat_data_t *base = data;

	/*
	 * First, blast through all of the data updating our array
	 * of active traps.  We keep an array of active traps to prevent
	 * printing lines for traps that are never seen -- while still printing
	 * lines for traps that have been seen only once on some CPU.
	 */
	for (i = 0; i < g_max_cpus; i++) {
		if (data[i].tdata_cpuid == -1)
			break;

		for (j = 0; j < TSTAT_NENT; j++) {
			if (!data[i].tdata_traps[j] || g_active[j])
				continue;

			g_active[j] = 1;
		}
	}

	data = base;

	for (done = 0; !done; data += g_cpus_per_line) {
		for (i = 0; i < g_cpus_per_line; i++) {
			if (&data[i] - base >= g_max_cpus)
				break;

			if ((id = data[i].tdata_cpuid) == -1)
				break;

			if (i == 0)
				(void) printf("vct name                |");

			(void) printf("   %scpu%d", id >= 100 ? "" :
			    id >= 10 ? " " : "  ", id);
		}

		if (i == 0)
			break;

		if (i != g_cpus_per_line)
			done = 1;

		(void) printf("\n------------------------+");

		for (j = 0; j < i; j++)
			(void) printf("---------");
		(void) printf("\n");

		for (j = 0; j < TSTAT_NENT; j++) {
			tstat_ent_t	*gtp;

			if ((!g_active[j]) || ((gtp = get_trap_ent(j)) == NULL))
				continue;

			(void) printf("%3x %-20s|", j, gtp->tent_name);
			for (k = 0; k < i; k++) {
				(void) printf(" %8lld", TSTAT_DELTA(&data[k],
				    &odata[data - base + k], tdata_traps[j]));
			}
			(void) printf("\n");
		}
		(void) printf("\n");
	}
}

static void
parsable_stats(tstat_data_t *data, tstat_data_t *odata)
{
	tstat_data_t *base;
	int i;

	for (base = data; data - base < g_max_cpus; data++, odata++) {
		if (data->tdata_cpuid == -1)
			break;

		for (i = 0; i < TSTAT_NENT; i++) {
			tstat_ent_t	*gtp;

			if ((!data->tdata_traps[i] && !g_active[i]) ||
			    ((gtp = get_trap_ent(i)) == NULL))
				continue;

			(void) printf("%lld %d %x %s ",
			    data->tdata_snapts - g_start, data->tdata_cpuid, i,
			    gtp->tent_name);

			(void) printf("%lld\n", TSTAT_DELTA(data, odata,
			    tdata_traps[i]));
		}
	}
}

static void
check_data(tstat_data_t *data, tstat_data_t *odata)
{
	tstat_data_t *ndata;
	int i;

	if (data->tdata_cpuid == -1) {
		/*
		 * The last CPU we were watching must have been DR'd out
		 * of the system.  Print a vaguely useful message and exit.
		 */
		fatal("all initially selected CPUs have been unconfigured\n");
	}

	/*
	 * If a CPU is DR'd out of the system, we'll stop receiving data
	 * for it.  CPUs are never added, however (that is, if a CPU is
	 * DR'd into the system, we won't automatically start receiving
	 * data for it).  We check for this by making sure that all of
	 * the CPUs present in the old data are present in the new data.
	 * If we find one missing in the new data, we correct the old data
	 * by removing the old CPU.  This assures that delta are printed
	 * correctly.
	 */
	for (i = 0; i < g_max_cpus; i++) {
		if (odata->tdata_cpuid == -1)
			return;

		if (data->tdata_cpuid != odata->tdata_cpuid)
			break;

		data = (tstat_data_t *)((uintptr_t)data + g_datasize);
		odata = (tstat_data_t *)((uintptr_t)odata + g_datasize);
	}

	if (i == g_max_cpus)
		return;

	/*
	 * If we're here, we know that the odata is a CPU which has been
	 * DR'd out.  We'll now smoosh it out of the old data.
	 */
	for (odata->tdata_cpuid = -1; i < g_max_cpus - 1; i++) {
		ndata = (tstat_data_t *)((uintptr_t)odata + g_datasize);
		bcopy(ndata, odata, g_datasize);
		ndata->tdata_cpuid = -1;
	}

	/*
	 * There may be other CPUs DR'd out; tail-call recurse.
	 */
	check_data(data, odata);
}

int
main(int argc, char **argv)
{
	processorid_t id;
	char *end;
	int c;
	ulong_t indefinite;
	long count = 0, rate = 0;
	int list = 0, parsable = 0;
	void (*print)(tstat_data_t *, tstat_data_t *);
	sigset_t set;

	struct {
		char opt;
		void (*print)(tstat_data_t *, tstat_data_t *);
		void (*parsable)(tstat_data_t *, tstat_data_t *);
		int repeat;
	} tab[] = {
		{ '\0',	print_stats,	parsable_stats,		0 },
		{ 'e',	print_stats,	parsable_stats,		1 },
		{ 't',	print_tlb,	parsable_tlb,		0 },
		{ 'T',	print_tlbpgsz,	parsable_tlbpgsz,	0 },
		{ -1,	NULL,		NULL,			0 }
	}, *tabent = NULL, *iter;

	uintptr_t offs = (uintptr_t)&tab->print - (uintptr_t)tab;

	/*
	 * If argv[0] is non-NULL, set argv[0] to keep any getopt(3C) output
	 * consistent with other error output.
	 */
	if (argv[0] != NULL)
		argv[0] = TSTAT_COMMAND;

	if ((g_fd = open(TSTAT_DEVICE, O_RDWR)) == -1)
		fatal("couldn't open " TSTAT_DEVICE);

	setup();

	while ((c = getopt(argc, argv, "alnNtTc:C:r:e:P")) != EOF) {
		/*
		 * First, check to see if this option changes our printing
		 * function.
		 */
		for (iter = tab; iter->opt >= 0; iter++) {
			if (c != iter->opt)
				continue;

			if (tabent != NULL) {
				if (tabent == iter) {
					if (tabent->repeat) {
						/*
						 * This option is allowed to
						 * have repeats; break out.
						 */
						break;
					}

					fatal("expected -%c at most once\n", c);
				}

				fatal("only one of -%c, -%c expected\n",
				    tabent->opt, c);
			}

			tabent = iter;
			break;
		}

		switch (c) {
		case 'a':
			g_absolute = 1;
			break;

		case 'e': {
			char *s = strtok(optarg, ",");

			while (s != NULL) {
				select_entry(s);
				s = strtok(NULL, ",");
			}

			break;
		}

		case 'l':
			list = 1;
			break;

		case 'n':
			/*
			 * This undocumented option prevents trapstat from
			 * actually switching the %tba to point to the
			 * interposing trap table.  It's very useful when
			 * debugging trapstat bugs:  one can specify "-n"
			 * and then examine the would-be interposing trap
			 * table without running the risk of RED stating.
			 */
			if (ioctl(g_fd, TSTATIOC_NOGO) == -1)
				fatal("TSTATIOC_NOGO");
			break;

		case 'N':
			/*
			 * This undocumented option forces trapstat to ignore
			 * its determined probe effect.  This may be useful
			 * if it is believed that the probe effect has been
			 * grossly overestimated.
			 */
			g_peffect = 0;
			break;

		case 't':
		case 'T':
			/*
			 * When running with TLB statistics, we want to
			 * minimize probe effect by running with all other
			 * entries explicitly disabled.
			 */
			if (ioctl(g_fd, TSTATIOC_NOENTRY) == -1)
				fatal("TSTATIOC_NOENTRY");

			if (ioctl(g_fd, TSTATIOC_TLBDATA) == -1)
				fatal("TSTATIOC_TLBDATA");
			break;

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

		case 'r': {
			rate = strtol(optarg, &end, 0);

			if (*end != '\0' ||
			    (rate == LONG_MAX && errno == ERANGE))
				fatal("invalid rate '%s'\n", optarg);

			if (rate <= 0)
				fatal("rate must be greater than zero\n");

			if (rate > TSTAT_MAX_RATE)
				fatal("rate may not exceed %d\n",
				    TSTAT_MAX_RATE);

			set_interval(NANOSEC / rate);
			break;
		}

		case 'P':
			offs = (uintptr_t)&tab->parsable - (uintptr_t)tab;
			parsable = 1;
			break;

		default:
			usage();
		}
	}

	if (list) {
		print_entries(stdout, parsable);
		exit(EXIT_SUCCESS);
	}

	if (optind != argc) {

		int interval = strtol(argv[optind], &end, 0);

		if (*end != '\0') {
			/*
			 * That wasn't a valid number.  It must be that we're
			 * to execute this command.
			 */
			switch (vfork()) {
			case 0:
				(void) close(g_fd);
				(void) sigprocmask(SIG_SETMASK, &g_oset, NULL);
				(void) execvp(argv[optind], &argv[optind]);

				/*
				 * No luck.  Set errno.
				 */
				g_exec_errno = errno;
				_exit(EXIT_FAILURE);
				/*NOTREACHED*/
			case -1:
				fatal("cannot fork");
				/*NOTREACHED*/
			default:
				break;
			}
		} else {
			if (interval <= 0)
				fatal("interval must be greater than zero.\n");

			if (interval == LONG_MAX && errno == ERANGE)
				fatal("invalid interval '%s'\n", argv[optind]);

			set_interval(NANOSEC * (hrtime_t)interval);

			if (++optind != argc) {
				char *s = argv[optind];

				count = strtol(s, &end, 0);

				if (*end != '\0' || count <= 0 ||
				    (count == LONG_MAX && errno == ERANGE))
					fatal("invalid count '%s'\n", s);
			}
		}
	} else {
		if (!rate)
			set_interval(NANOSEC);
	}

	if (tabent == NULL)
		tabent = tab;

	print = *(void(**)(tstat_data_t *, tstat_data_t *))
	    ((uintptr_t)tabent + offs);

	for (id = 0; id < g_max_cpus; id++) {
		if (!g_selected[id])
			continue;

		if (ioctl(g_fd, TSTATIOC_CPU, id) == -1)
			fatal("TSTATIOC_CPU failed for cpu %d", id);
	}

	g_start = gethrtime();

	if (ioctl(g_fd, TSTATIOC_GO) == -1)
		fatal("TSTATIOC_GO failed");

	if (ioctl(g_fd, TSTATIOC_READ, g_data[g_gen ^ 1]) == -1)
		fatal("initial TSTATIOC_READ failed");

	(void) sigemptyset(&set);

	for (indefinite = (count == 0); indefinite || count; count--) {

		(void) sigsuspend(&set);

		if (g_winch) {
			g_winch = 0;
			continue;
		}

		if (g_child_exited && g_exec_errno != 0) {
			errno = g_exec_errno;
			fatal("could not execute %s", argv[optind]);
		}

		if (ioctl(g_fd, TSTATIOC_READ, g_data[g_gen]) == -1)
			fatal("TSTATIOC_READ failed");

		/*
		 * Before we blithely print the data, we need to
		 * make sure that we haven't lost a CPU.
		 */
		check_data(g_data[g_gen], g_data[g_gen ^ 1]);
		(*print)(g_data[g_gen], g_data[g_gen ^ 1]);
		(void) fflush(stdout);

		if (g_child_exited) {
			if (WIFEXITED(g_child_status)) {
				if (WEXITSTATUS(g_child_status) == 0)
					break;

				(void) fprintf(stderr, TSTAT_COMMAND ": "
				    "warning: %s exited with code %d\n",
				    argv[optind], WEXITSTATUS(g_child_status));
			} else {
				(void) fprintf(stderr, TSTAT_COMMAND ": "
				    "warning: %s died on signal %d\n",
				    argv[optind], WTERMSIG(g_child_status));
			}
			break;
		}

		check_pset();

		g_gen ^= 1;
	}

	return (0);
}
