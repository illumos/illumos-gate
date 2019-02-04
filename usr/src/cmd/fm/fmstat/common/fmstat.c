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

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <fm/fmd_adm.h>

#include <strings.h>
#include <limits.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <poll.h>
#include <locale.h>

#include "statcommon.h"

#define	FMSTAT_EXIT_SUCCESS	0
#define	FMSTAT_EXIT_ERROR	1
#define	FMSTAT_EXIT_USAGE	2

static const struct stats {
	fmd_stat_t module;
	fmd_stat_t authority;
	fmd_stat_t state;
	fmd_stat_t loadtime;
	fmd_stat_t snaptime;
	fmd_stat_t received;
	fmd_stat_t discarded;
	fmd_stat_t retried;
	fmd_stat_t replayed;
	fmd_stat_t lost;
	fmd_stat_t dispatched;
	fmd_stat_t dequeued;
	fmd_stat_t prdequeued;
	fmd_stat_t accepted;
	fmd_stat_t memtotal;
	fmd_stat_t buftotal;
	fmd_stat_t caseopen;
	fmd_stat_t casesolved;
	fmd_stat_t wcnt;
	fmd_stat_t wtime;
	fmd_stat_t wlentime;
	fmd_stat_t wlastupdate;
	fmd_stat_t dtime;
	fmd_stat_t dlastupdate;
} stats_template = {
	{ "module", FMD_TYPE_STRING },
	{ "authority", FMD_TYPE_STRING },
	{ "state", FMD_TYPE_STRING },
	{ "loadtime", FMD_TYPE_TIME },
	{ "snaptime", FMD_TYPE_TIME },
	{ "received", FMD_TYPE_UINT64 },
	{ "discarded", FMD_TYPE_UINT64 },
	{ "retried", FMD_TYPE_UINT64 },
	{ "replayed", FMD_TYPE_UINT64 },
	{ "lost", FMD_TYPE_UINT64 },
	{ "dispatched", FMD_TYPE_UINT64 },
	{ "dequeued", FMD_TYPE_UINT64 },
	{ "prdequeued", FMD_TYPE_UINT64 },
	{ "accepted", FMD_TYPE_UINT64 },
	{ "memtotal", FMD_TYPE_SIZE },
	{ "buftotal", FMD_TYPE_SIZE },
	{ "caseopen", FMD_TYPE_UINT64 },
	{ "casesolved", FMD_TYPE_UINT64 },
	{ "wcnt", FMD_TYPE_UINT32 },
	{ "wtime", FMD_TYPE_TIME },
	{ "wlentime", FMD_TYPE_TIME },
	{ "wlastupdate", FMD_TYPE_TIME },
	{ "dtime", FMD_TYPE_TIME },
	{ "dlastupdate", FMD_TYPE_TIME },
};

static const char *g_pname;
static fmd_adm_t *g_adm;

static struct modstats {
	char *m_name;
	struct modstats *m_next;
	struct stats m_stbuf[2];
	int m_stidx;
	int m_id;
	struct stats *m_old;
	struct stats *m_new;
	double m_wait;
	double m_svc;
	double m_pct_b;
	double m_pct_w;
} *g_mods;

static uint_t timestamp_fmt = NODATE;

#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"		/* Use this only if it isn't */
#endif

static void
vwarn(const char *format, va_list ap)
{
	int err = errno;

	(void) fprintf(stderr, "%s: ", g_pname);

	if (format != NULL)
		(void) vfprintf(stderr, format, ap);

	errno = err; /* restore errno for fmd_adm_errmsg() */

	if (format == NULL)
		(void) fprintf(stderr, "%s\n", fmd_adm_errmsg(g_adm));
	else if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, ": %s\n", fmd_adm_errmsg(g_adm));
}

/*PRINTFLIKE1*/
void
warn(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vwarn(format, ap);
	va_end(ap);
}

/*PRINTFLIKE1*/
void
die(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vwarn(format, ap);
	va_end(ap);

	fmd_adm_close(g_adm);
	exit(FMSTAT_EXIT_ERROR);
}

static char *
time2str(char *buf, size_t len, uint64_t time)
{
	static const struct unit {
		const char *u_name;
		hrtime_t u_mul;
	} units[] = {
		{ "d",	NANOSEC * (hrtime_t)(24 * 60 * 60) },
		{ "h",	NANOSEC * (hrtime_t)(60 * 60) },
		{ "m",	NANOSEC * (hrtime_t)60 },
		{ "s",	NANOSEC / SEC },
		{ "ms",	NANOSEC / MILLISEC },
		{ "us",	NANOSEC / MICROSEC },
		{ "ns",	NANOSEC / NANOSEC },
	};

	const struct unit *up;

	for (up = units; time % up->u_mul != 0; up++)
		continue; /* find largest unit of which 'time' is a multiple */

	(void) snprintf(buf, len, "%llu%s", time / up->u_mul, up->u_name);
	return (buf);
}

static char *
size2str(char *buf, size_t len, uint64_t size)
{
	static const char units[] = "bKMGTPE";
	const uint64_t scale = 1024;
	const char *up = units;
	uint64_t osize = 0;

	/*
	 * Convert the input size to a round number of the appropriately
	 * scaled units (saved in 'size') and a remainder (saved in 'osize').
	 */
	while (size >= scale && up < (units + sizeof (units) - 2)) {
		up++;
		osize = size;
		size = (size + (scale / 2)) / scale;
	}

	/*
	 * Format the result using at most one decimal place and the unit
	 * depending upon the amount of remainder (same as df -h algorithm).
	 */
	if (osize != 0 && (osize / scale) < 10)
		(void) snprintf(buf, len, "%.1f%c", (float)osize / scale, *up);
	else if (size != 0)
		(void) snprintf(buf, len, "%llu%c", size, *up);
	else
		(void) snprintf(buf, len, "0");

	return (buf);
}

static uint64_t
u64delta(uint64_t old, uint64_t new)
{
	return (new >= old ? (new - old) : ((UINT64_MAX - old) + new + 1));
}

static struct modstats *
modstat_create(const char *name, id_t id)
{
	struct modstats *mp = malloc(sizeof (struct modstats));

	if (mp == NULL)
		return (NULL);

	bzero(mp, sizeof (struct modstats));

	if (name != NULL && (mp->m_name = strdup(name)) == NULL) {
		free(mp);
		return (NULL);
	}

	mp->m_id = id;
	mp->m_next = g_mods;
	g_mods = mp;
	return (mp);
}

/*
 * Given a statistics buffer containing event queue statistics, compute the
 * common queue statistics for the given module and store the results in 'mp'.
 * We set m_new and m_old for the caller, and store the compute values of
 * m_svc, m_wait, m_pct_w, and m_pct_b there as well.  The caller must not free
 * 'ams' until after using the results as m_new may contain pointers to it.
 */
static void
modstat_compute(struct modstats *mp, fmd_adm_stats_t *ams)
{
	static fmd_stat_t *t_beg = (fmd_stat_t *)(&stats_template + 0);
	static fmd_stat_t *t_end = (fmd_stat_t *)(&stats_template + 1);

	struct stats *old, *new;
	fmd_stat_t *tsp, *nsp, *sp;
	double elapsed, avg_w, avg_d;
	uint64_t delta;

	old = mp->m_old = &mp->m_stbuf[mp->m_stidx];
	mp->m_stidx = 1 - mp->m_stidx;
	new = mp->m_new = &mp->m_stbuf[mp->m_stidx];

	/*
	 * The statistics can come in any order; we compare each one to the
	 * template of statistics of interest, find the matching ones, and copy
	 * their values into the appropriate slot of the 'new' stats.
	 */
	for (nsp = ams->ams_buf; nsp < ams->ams_buf + ams->ams_len; nsp++) {
		for (tsp = t_beg; tsp < t_end; tsp++) {
			const char *p = strrchr(nsp->fmds_name, '.');

			/*
			 * The fmd queue stats can either be named fmd.<name>
			 * or fmd.xprt.%u.<name> depending on whether we're
			 * looking at the module queue or the transport queue.
			 * So we match using the patterns fmd.* and *.<name>
			 * and store only the value of <name> in stats_template.
			 */
			if (p == NULL || strcmp(p + 1, tsp->fmds_name) != 0 ||
			    strncmp(nsp->fmds_name, "fmd.", 4) != 0)
				continue; /* continue until we match the stat */

			if (tsp->fmds_type != nsp->fmds_type) {
				warn("%s has unexpected type (%u != %u)\n",
				    nsp->fmds_name, tsp->fmds_type,
				    nsp->fmds_type);
			} else {
				sp = (fmd_stat_t *)new + (tsp - t_beg);
				sp->fmds_value = nsp->fmds_value;
			}
		}
	}

	/*
	 * Compute the elapsed time by taking the delta between 'snaptime', or
	 * or between snaptime and loadtime if there is no previous snapshot.
	 * If delta is zero, set it to 1sec so we don't divide by zero later.
	 */
	delta = u64delta(old->snaptime.fmds_value.ui64 ?
	    old->snaptime.fmds_value.ui64 : old->loadtime.fmds_value.ui64,
	    new->snaptime.fmds_value.ui64);

	elapsed = delta ? (double)delta : (double)NANOSEC;

	/*
	 * Compute average wait queue len by taking the delta in the wait queue
	 * len * time products (wlentime stat) and dividing by the elapsed time.
	 */
	delta = u64delta(old->wlentime.fmds_value.ui64,
	    new->wlentime.fmds_value.ui64);

	if (delta != 0)
		mp->m_wait = (double)delta / elapsed;
	else
		mp->m_wait = 0.0;

	/*
	 * Compute average wait time by taking the delta in the wait queue time
	 * (wtime) and dividing by the delta in the number of dispatches.
	 */
	delta = u64delta(old->dispatched.fmds_value.ui64,
	    new->dispatched.fmds_value.ui64);

	if (delta != 0) {
		avg_w = (double)u64delta(old->wtime.fmds_value.ui64,
		    new->wtime.fmds_value.ui64) / (double)delta;
	} else
		avg_w = 0.0;

	/*
	 * Compute average dispatch time by taking the delta in the dispatch
	 * time (dtime) and dividing by the delta in the number of dequeues.
	 */
	delta = u64delta(old->dequeued.fmds_value.ui64,
	    new->dequeued.fmds_value.ui64);

	if (delta != 0) {
		avg_d = (double)u64delta(old->dtime.fmds_value.ui64,
		    new->dtime.fmds_value.ui64) / (double)delta;
	} else
		avg_d = 0.0;

	/*
	 * Finally compute the average overall service time by adding together
	 * the average wait and dispatch times and converting to milliseconds.
	 */
	mp->m_svc = ((avg_w + avg_d) * (double)MILLISEC) / (double)NANOSEC;

	/*
	 * Compute the %wait and %busy times by taking the delta in wait and
	 * busy times, dividing by the elapsed time, and multiplying by 100.
	 */
	delta = u64delta(old->wtime.fmds_value.ui64,
	    new->wtime.fmds_value.ui64);

	if (delta != 0)
		mp->m_pct_w = ((double)delta / elapsed) * 100.0;
	else
		mp->m_pct_w = 0.0;

	delta = u64delta(old->dtime.fmds_value.ui64,
	    new->dtime.fmds_value.ui64);

	if (delta != 0)
		mp->m_pct_b = ((double)delta / elapsed) * 100.0;
	else
		mp->m_pct_b = 0.0;
}

/*ARGSUSED*/
static void
stat_one_xprt(id_t id, void *ignored)
{
	fmd_adm_stats_t ams;
	struct modstats *mp;

	if (fmd_adm_xprt_stats(g_adm, id, &ams) != 0) {
		warn("failed to retrieve statistics for transport %d", (int)id);
		return;
	}

	for (mp = g_mods; mp != NULL; mp = mp->m_next) {
		if (mp->m_id == id)
			break;
	}

	if (mp == NULL && (mp = modstat_create(NULL, id)) == NULL) {
		warn("failed to allocate memory for transport %d", (int)id);
		(void) fmd_adm_stats_free(g_adm, &ams);
		return;
	}

	modstat_compute(mp, &ams);

	(void) printf("%3d %5s %7llu %7llu %7llu %7llu "
	    "%4.1f %6.1f %3.0f %3.0f %s\n", (int)id,
	    mp->m_new->state.fmds_value.str,
	    u64delta(mp->m_old->prdequeued.fmds_value.ui64,
	    mp->m_new->prdequeued.fmds_value.ui64),
	    u64delta(mp->m_old->received.fmds_value.ui64,
	    mp->m_new->received.fmds_value.ui64),
	    u64delta(mp->m_old->discarded.fmds_value.ui64,
	    mp->m_new->discarded.fmds_value.ui64),
	    u64delta(mp->m_old->lost.fmds_value.ui64,
	    mp->m_new->lost.fmds_value.ui64),
	    mp->m_wait, mp->m_svc, mp->m_pct_w, mp->m_pct_b,
	    mp->m_new->module.fmds_value.str);

	(void) fmd_adm_stats_free(g_adm, &ams);
}

static void
stat_xprt(void)
{
	(void) printf("%3s %5s %7s %7s %7s %7s %4s %6s %3s %3s %s\n",
	    "id", "state", "ev_send", "ev_recv", "ev_drop", "ev_lost",
	    "wait", "svc_t", "%w", "%b", "module");

	if (fmd_adm_xprt_iter(g_adm, stat_one_xprt, NULL) != 0)
		die("failed to retrieve list of transports");
}

static void
stat_one_xprt_auth(id_t id, void *arg)
{
	const char *module = arg;
	fmd_adm_stats_t ams;
	struct modstats *mp;

	if (fmd_adm_xprt_stats(g_adm, id, &ams) != 0) {
		warn("failed to retrieve statistics for transport %d", (int)id);
		return;
	}

	for (mp = g_mods; mp != NULL; mp = mp->m_next) {
		if (mp->m_id == id)
			break;
	}

	if (mp == NULL && (mp = modstat_create(NULL, id)) == NULL) {
		warn("failed to allocate memory for transport %d", (int)id);
		(void) fmd_adm_stats_free(g_adm, &ams);
		return;
	}

	modstat_compute(mp, &ams);

	if (module == NULL ||
	    strcmp(module, mp->m_new->module.fmds_value.str) == 0) {
		(void) printf("%3d %5s %-18s  %s\n", (int)id,
		    mp->m_new->state.fmds_value.str,
		    mp->m_new->module.fmds_value.str,
		    mp->m_new->authority.fmds_value.str ?
		    mp->m_new->authority.fmds_value.str : "-");
	}

	(void) fmd_adm_stats_free(g_adm, &ams);
}

static void
stat_xprt_auth(const char *module)
{
	(void) printf("%3s %5s %-18s  %s\n",
	    "id", "state", "module", "authority");

	if (fmd_adm_xprt_iter(g_adm, stat_one_xprt_auth, (void *)module) != 0)
		die("failed to retrieve list of transports");
}

/*ARGSUSED*/
static int
stat_one_fmd(const fmd_adm_modinfo_t *ami, void *ignored)
{
	char memsz[8], bufsz[8];
	fmd_adm_stats_t ams;
	struct modstats *mp;

	if (fmd_adm_module_stats(g_adm, ami->ami_name, &ams) != 0) {
		warn("failed to retrieve statistics for %s", ami->ami_name);
		return (0); /* continue on to the next module */
	}

	for (mp = g_mods; mp != NULL; mp = mp->m_next) {
		if (strcmp(mp->m_name, ami->ami_name) == 0)
			break;
	}

	if (mp == NULL && (mp = modstat_create(ami->ami_name, 0)) == NULL) {
		warn("failed to allocate memory for %s", ami->ami_name);
		(void) fmd_adm_stats_free(g_adm, &ams);
		return (0);
	}

	modstat_compute(mp, &ams);

	(void) printf("%-18s %7llu %7llu %4.1f %6.1f %3.0f %3.0f "
	    "%5llu %5llu %6s %6s\n", ami->ami_name,
	    u64delta(mp->m_old->prdequeued.fmds_value.ui64,
	    mp->m_new->prdequeued.fmds_value.ui64),
	    u64delta(mp->m_old->accepted.fmds_value.ui64,
	    mp->m_new->accepted.fmds_value.ui64),
	    mp->m_wait, mp->m_svc, mp->m_pct_w, mp->m_pct_b,
	    mp->m_new->caseopen.fmds_value.ui64,
	    mp->m_new->casesolved.fmds_value.ui64,
	    size2str(memsz, sizeof (memsz),
	    mp->m_new->memtotal.fmds_value.ui64),
	    size2str(bufsz, sizeof (bufsz),
	    mp->m_new->buftotal.fmds_value.ui64));

	(void) fmd_adm_stats_free(g_adm, &ams);
	return (0);
}

static void
stat_fmd(void)
{
	(void) printf("%-18s %7s %7s %4s %6s %3s %3s %5s %5s %6s %6s\n",
	    "module", "ev_recv", "ev_acpt", "wait", "svc_t", "%w", "%b",
	    "open", "solve", "memsz", "bufsz");

	if (fmd_adm_module_iter(g_adm, stat_one_fmd, NULL) != 0)
		die("failed to retrieve list of modules");
}

static void
stat_mod(const char *name, int aflag, int zflag)
{
	fmd_adm_stats_t ams;
	fmd_stat_t *sp;
	char buf[64];

	if (fmd_adm_stats_read(g_adm, name, &ams) != 0) {
		die("failed to retrieve statistics for %s",
		    name ? name : "fmd(1M)");
	}

	(void) printf("%20s %-16s %s\n", "NAME", "VALUE", "DESCRIPTION");

	for (sp = ams.ams_buf; sp < ams.ams_buf + ams.ams_len; sp++) {
		if (aflag == 0 && strncmp(sp->fmds_name, "fmd.", 4) == 0)
			continue; /* skip fmd-internal stats unless -a used */

		if (zflag) {
			switch (sp->fmds_type) {
			case FMD_TYPE_INT32:
			case FMD_TYPE_UINT32:
				if (sp->fmds_value.ui32 == 0)
					continue;
				break;
			case FMD_TYPE_INT64:
			case FMD_TYPE_UINT64:
			case FMD_TYPE_TIME:
			case FMD_TYPE_SIZE:
				if (sp->fmds_value.ui64 == 0)
					continue;
				break;
			case FMD_TYPE_STRING:
				if (sp->fmds_value.str == NULL ||
				    sp->fmds_value.str[0] == '\0')
					continue;
				break;
			}
		}

		(void) printf("%20s ", sp->fmds_name);

		switch (sp->fmds_type) {
		case FMD_TYPE_BOOL:
			(void) printf("%-16s",
			    sp->fmds_value.bool ? "true" : "false");
			break;
		case FMD_TYPE_INT32:
			(void) printf("%-16d", sp->fmds_value.i32);
			break;
		case FMD_TYPE_UINT32:
			(void) printf("%-16u", sp->fmds_value.ui32);
			break;
		case FMD_TYPE_INT64:
			(void) printf("%-16lld", sp->fmds_value.i64);
			break;
		case FMD_TYPE_UINT64:
			(void) printf("%-16llu", sp->fmds_value.ui64);
			break;
		case FMD_TYPE_STRING:
			(void) printf("%-16s", sp->fmds_value.str ?
			    sp->fmds_value.str : "<<null>>");
			break;
		case FMD_TYPE_TIME:
			(void) printf("%-16s",
			    time2str(buf, sizeof (buf), sp->fmds_value.ui64));
			break;
		case FMD_TYPE_SIZE:
			(void) printf("%-16s",
			    size2str(buf, sizeof (buf), sp->fmds_value.ui64));
			break;
		default:
			(void) snprintf(buf, sizeof (buf),
			    "<<type=%u>>\n", sp->fmds_type);
			(void) printf("%-16s", buf);
		}

		(void) printf(" %s\n", sp->fmds_desc);
	}

	(void) fmd_adm_stats_free(g_adm, &ams);
}

/*ARGSUSED*/
static int
stat_one_serd(const fmd_adm_serdinfo_t *asi, void *ignored)
{
	char buf1[32], buf2[32], n[32];

	(void) snprintf(n, sizeof (n), ">%llu", asi->asi_n);

	(void) printf("%-36s %3s %5s %3u %24s %s\n",
	    asi->asi_name, n, time2str(buf1, sizeof (buf1), asi->asi_t),
	    asi->asi_count, time2str(buf2, sizeof (buf2), asi->asi_delta),
	    (asi->asi_flags & FMD_ADM_SERD_FIRED) ? "fire" : "pend");

	return (0);
}

static void
stat_mod_serd(const char *name)
{
	(void) printf("%-36s %3s %5s %3s %24s %4s\n",
	    "NAME", ">N", "T", "CNT", "DELTA", "STAT");

	if (fmd_adm_serd_iter(g_adm, name, stat_one_serd, NULL) != 0)
		die("failed to retrieve serd engines for %s", name);
}

static int
getint(const char *name, const char *s)
{
	long val;
	char *p;

	errno = 0;
	val = strtol(s, &p, 10);

	if (errno != 0 || p == s || *p != '\0' || val < 0 || val > INT_MAX) {
		(void) fprintf(stderr, "%s: invalid %s argument -- %s\n",
		    g_pname, name, s);
		exit(FMSTAT_EXIT_USAGE);
	}

	return ((int)val);
}

static uint32_t
getu32(const char *name, const char *s)
{
	u_longlong_t val;
	char *p;

	errno = 0;
	val = strtoull(s, &p, 0);

	if (errno != 0 || p == s || *p != '\0' || val > UINT32_MAX) {
		(void) fprintf(stderr, "%s: invalid %s argument -- %s\n",
		    g_pname, name, s);
		exit(FMSTAT_EXIT_USAGE);
	}

	return ((uint32_t)val);
}

static int
usage(FILE *fp)
{
	(void) fprintf(fp, "Usage: %s [-astTz] [-m module] "
	    "[-P prog] [-d d|u] [interval [count]]\n\n", g_pname);

	(void) fprintf(fp,
	    "\t-a show all statistics, including those kept by fmd\n"
	    "\t-d display a timestamp in date (d) or unix time_t (u)\n"
	    "\t-m show module-specific statistics\n"
	    "\t-P connect to alternate fmd program\n"
	    "\t-s show module-specific serd engines\n"
	    "\t-t show transport-specific statistics\n"
	    "\t-T show transport modules and authorities\n"
	    "\t-z suppress zero-valued statistics\n");

	return (FMSTAT_EXIT_USAGE);
}

int
main(int argc, char *argv[])
{
	int opt_a = 0, opt_s = 0, opt_t = 0, opt_T = 0, opt_z = 0;
	const char *opt_m = NULL;
	int msec = 0, iter = 1;

	uint32_t program;
	char *p;
	int c;

	if ((p = strrchr(argv[0], '/')) == NULL)
		g_pname = argv[0];
	else
		g_pname = p + 1;

	if ((p = getenv("FMD_PROGRAM")) != NULL)
		program = getu32("$FMD_PROGRAM", p);
	else
		program = FMD_ADM_PROGRAM;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "ad:m:P:stTz")) != EOF) {
		switch (c) {
		case 'a':
			opt_a++;
			break;
		case 'd':
			if (optarg) {
				if (*optarg == 'u')
					timestamp_fmt = UDATE;
				else if (*optarg == 'd')
					timestamp_fmt = DDATE;
				else
					return (usage(stderr));
			} else {
				return (usage(stderr));
			}
			break;
		case 'm':
			opt_m = optarg;
			break;
		case 'P':
			program = getu32("program", optarg);
			break;
		case 's':
			opt_s++;
			break;
		case 't':
			opt_t++;
			break;
		case 'T':
			opt_T++;
			break;
		case 'z':
			opt_z++;
			break;
		default:
			return (usage(stderr));
		}
	}

	if (optind < argc) {
		msec = getint("interval", argv[optind++]) * MILLISEC;
		iter = -1;
	}

	if (optind < argc)
		iter = getint("count", argv[optind++]);

	if (optind < argc)
		return (usage(stderr));

	if (opt_t != 0 && (opt_m != NULL || opt_s != 0)) {
		(void) fprintf(stderr,
		    "%s: -t cannot be used with -m or -s\n", g_pname);
		return (FMSTAT_EXIT_USAGE);
	}

	if (opt_t != 0 && opt_T != 0) {
		(void) fprintf(stderr,
		    "%s: -t and -T are mutually exclusive options\n", g_pname);
		return (FMSTAT_EXIT_USAGE);
	}

	if (opt_m == NULL && opt_s != 0) {
		(void) fprintf(stderr,
		    "%s: -s requires -m <module>\n", g_pname);
		return (FMSTAT_EXIT_USAGE);
	}

	if ((g_adm = fmd_adm_open(NULL, program, FMD_ADM_VERSION)) == NULL)
		die(NULL); /* fmd_adm_errmsg() has enough info */

	while (iter < 0 || iter-- > 0) {
		if (timestamp_fmt != NODATE)
			print_timestamp(timestamp_fmt);
		if (opt_s)
			stat_mod_serd(opt_m);
		else if (opt_T)
			stat_xprt_auth(opt_m);
		else if (opt_a || opt_m)
			stat_mod(opt_m, opt_a, opt_z);
		else if (opt_t)
			stat_xprt();
		else
			stat_fmd();

		if (iter != 0) {
			(void) poll(NULL, 0, msec);
			(void) putchar('\n');
		}
	}

	fmd_adm_close(g_adm);
	return (FMSTAT_EXIT_SUCCESS);
}
