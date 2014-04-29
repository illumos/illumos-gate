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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * rcapd is a long-running daemon enforcing project-based resource caps (see
 * rcapd(1M)).  Each instance of a process aggregate (project or, generically,
 * "collection") may have a memory cap.  A single thread monitors the resource
 * utilization of capped collections, enforces caps when they are exceeded (and
 * other conditions are met), and incorporates changes in configuration or
 * caps.  Each of these actions occurs not more frequently than the rate
 * specified with rcapadm(1M).
 */

#include <sys/priocntl.h>
#include <sys/proc.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <kstat.h>
#include <libintl.h>
#include <limits.h>
#include <locale.h>
#include <priv.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <libscf.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <zone.h>
#include <assert.h>
#include <sys/vm_usage.h>
#include "rcapd.h"
#include "rcapd_mapping.h"
#include "rcapd_rfd.h"
#include "rcapd_stat.h"
#include "utils.h"

#define	POSITIVE_MIN(x, y) \
	(((x) <= 0) ? (y) : ((y) <= 0) ? (x) : MIN(x, y))
#define	NEXT_EVENT_TIME(base, seconds) \
	(((int)seconds > 0) ? (base + (hrtime_t)seconds * (hrtime_t)NANOSEC) \
	: (hrtime_t)0)
#define	NEXT_REPORT_EVENT_TIME(base, seconds) \
	((rcfg.rcfg_stat_file[0] != 0) ?  \
	    NEXT_EVENT_TIME(gethrtime(), seconds) : (hrtime_t)0)
#define	EVENT_TIME(time, eventtime) \
	(((time) > (eventtime)) && (eventtime) != 0)
#define	STAT_TEMPLATE_SUFFIX	".XXXXXX"	/* suffix of mkstemp() arg */
#define	DAEMON_UID		1		/* uid to use */

#define	CAPPED_PROJECT	0x01
#define	CAPPED_ZONE	0x02

typedef struct soft_scan_arg {
	uint64_t ssa_sum_excess;
	int64_t ssa_scan_goal;
	boolean_t ssa_project_over_cap;
} soft_scan_arg_t;

typedef struct sample_col_arg {
	boolean_t sca_any_over_cap;
	boolean_t sca_project_over_cap;
} sample_col_arg_t;


static int debug_mode = 0;		/* debug mode flag */
static pid_t rcapd_pid;			/* rcapd's pid to ensure it's not */
					/* scanned */
static kstat_ctl_t *kctl;		/* kstat chain */
static int memory_pressure = 0;		/* physical memory utilization (%) */
static int memory_pressure_sample = 0;	/* count of samples */
static long page_size_kb = 0;		/* system page size in KB */
static size_t nvmu_vals = 0;		/* # of kernel RSS/swap vals in array */
static size_t vmu_vals_len = 0;		/* size of RSS/swap vals array */
static vmusage_t *vmu_vals = NULL;	/* snapshot of kernel RSS/swap values */
static hrtime_t next_report;		/* time of next report */
static int termination_signal = 0;	/* terminating signal */
static zoneid_t my_zoneid = (zoneid_t)-1;
static lcollection_t *gz_col;		/* global zone collection */

rcfg_t rcfg;
/*
 * Updated when we re-read the collection configurations if this rcapd instance
 * is running in the global zone and the global zone is capped.
 */
boolean_t gz_capped = B_FALSE;

/*
 * Flags.
 */
static int ever_ran;
int should_run;
static int should_reconfigure;

static int verify_statistics(void);
static int update_statistics(void);

/*
 * Checks if a process is marked 'system'.  Returns FALSE only when it is not.
 */
static boolean_t
proc_issystem(pid_t pid)
{
	char pc_clname[PC_CLNMSZ];

	if (priocntl(P_PID, pid, PC_GETXPARMS, NULL, PC_KY_CLNAME, pc_clname,
	    PC_KY_NULL) != -1) {
		return (strcmp(pc_clname, "SYS") == 0);
	} else {
		debug("cannot get class-specific scheduling parameters; "
		    "assuming system process\n");
		return (B_TRUE);
	}
}

static void
lprocess_insert_mark(psinfo_t *psinfop)
{
	pid_t pid = psinfop->pr_pid;
	/* flag indicating whether the process should be scanned. */
	int unscannable = psinfop->pr_nlwp == 0;
	rcid_t colid;
	lcollection_t *lcol;
	lprocess_t *lproc;

	/*
	 * Determine which collection to put this process into.  We only have
	 * to worry about tracking both zone and project capped processes if
	 * this rcapd instance is running in the global zone, since we'll only
	 * see processes in our own projects in a non-global zone.  In the
	 * global zone, if the process belongs to a non-global zone, we only
	 * need to track it for the capped non-global zone collection.  For
	 * global zone processes, we first attempt to put the process into a
	 * capped project collection.  On the second pass into this function
	 * the projid will be cleared so we will just track the process for the
	 * global zone collection as a whole.
	 */
	if (psinfop->pr_zoneid == my_zoneid && psinfop->pr_projid != -1) {
		colid.rcid_type = RCIDT_PROJECT;
		colid.rcid_val = psinfop->pr_projid;
	} else {
		/* try to add to zone collection */
		colid.rcid_type = RCIDT_ZONE;
		colid.rcid_val = psinfop->pr_zoneid;
	}

	if ((lcol = lcollection_find(&colid)) == NULL)
		return;

	/*
	 * If the process is already being tracked, update the unscannable flag,
	 * as determined by the caller, from the process's psinfo.
	 */
	lproc = lcol->lcol_lprocess;
	while (lproc != NULL) {
		if (lproc->lpc_pid == pid) {
			lproc->lpc_mark = 1;
			if (unscannable != 0 && lproc->lpc_unscannable == 0) {
				debug("process %d: became unscannable\n",
				    (int)lproc->lpc_pid);
				lproc->lpc_unscannable = 1;
			}
			return;
		}
		lproc = lproc->lpc_next;
	}

	/*
	 * We've fallen off the list without finding our current process;
	 * insert it at the list head.
	 */
	if ((lproc = malloc(sizeof (*lproc))) == NULL)
		debug("insufficient memory to track new process %d", (int)pid);
	else {
		(void) bzero(lproc, sizeof (*lproc));
		lproc->lpc_pid = pid;
		lproc->lpc_mark = 1;
		lproc->lpc_collection = lcol;
		lproc->lpc_psinfo_fd = -1;
		lproc->lpc_pgdata_fd = -1;
		lproc->lpc_xmap_fd = -1;

		/*
		 * If the caller didn't flag this process as unscannable
		 * already, do some more checking.
		 */
		lproc->lpc_unscannable = unscannable || proc_issystem(pid);

#ifdef DEBUG
		/*
		 * Verify the sanity of lprocess.  It should not contain the
		 * process we are about to prepend.
		 */
		if (lcollection_member(lcol, lproc)) {
			lprocess_t *cur = lcol->lcol_lprocess;
			debug("The collection %lld already has these members, "
			    "including me, %d!\n",
			    (long long)lcol->lcol_id.rcid_val,
			    (int)lproc->lpc_pid);
			while (cur != NULL) {
				debug("\t%d\n", (int)cur->lpc_pid);
				cur = cur->lpc_next;
			}
			info(gettext("process already on lprocess\n"));
			abort();
		}
#endif /* DEBUG */
		lproc->lpc_next = lcol->lcol_lprocess;
		if (lproc->lpc_next != NULL)
			lproc->lpc_next->lpc_prev = lproc;
		lproc->lpc_prev = NULL;
		lcol->lcol_lprocess = lproc;

		debug("tracking %s %ld %d %s%s\n",
		    (colid.rcid_type == RCIDT_PROJECT ? "project" : "zone"),
		    (long)colid.rcid_val,
		    (int)pid, psinfop->pr_psargs,
		    (lproc->lpc_unscannable != 0) ? " (not scannable)" : "");
		lcol->lcol_stat.lcols_proc_in++;
	}
}

static int
list_walk_process_cb(lcollection_t *lcol, void *arg)
{
	int (*cb)(lcollection_t *, lprocess_t *) =
	    (int(*)(lcollection_t *, lprocess_t *))arg;
	lprocess_t *member;
	lprocess_t *next;

	member = lcol->lcol_lprocess;
	while (member != NULL) {
		pid_t pid = member->lpc_pid;
		next = member->lpc_next;

		debug_high("list_walk_all lpc %d\n", (int)pid);
		if (cb(lcol, member) != 0) {
			debug_high("list_walk_all aborted at lpc %d\n",
			    (int)pid);
			return (1);
		}
		member = next;
	}

	return (0);
}

/*
 * Invoke the given callback for each process in each collection.  Callbacks
 * are allowed to change the linkage of the process on which they act.
 */
static void
list_walk_all(int (*cb)(lcollection_t *, lprocess_t *))
{
	list_walk_collection(list_walk_process_cb, (void *)cb);
}

static void
revoke_psinfo(rfd_t *rfd)
{
	lprocess_t *lpc = (lprocess_t *)rfd->rfd_data;

	if (lpc != NULL) {
		debug("revoking psinfo fd for process %d\n", (int)lpc->lpc_pid);
		ASSERT(lpc->lpc_psinfo_fd != -1);
		lpc->lpc_psinfo_fd = -1;
	} else
		debug("revoking psinfo fd for unknown process\n");
}

/*
 * Retrieve a process's psinfo via an already-opened or new file descriptor.
 * The supplied descriptor will be closed on failure.  An optional callback
 * will be invoked with the last descriptor tried, and a supplied callback
 * argument, as its arguments, such that the new descriptor may be cached, or
 * an old one may be invalidated.  If the result of the callback is zero, the
 * the caller is to assume responsibility for the file descriptor, to close it
 * with rfd_close().
 *
 * On failure, a nonzero value is returned.
 */
int
get_psinfo(pid_t pid, psinfo_t *psinfo, int cached_fd,
    int(*fd_update_cb)(void *, int), void *arg, lprocess_t *lpc)
{
	int fd;
	int can_try_uncached;

	ASSERT(!(cached_fd > 0 && fd_update_cb == NULL));

	do {
		if (cached_fd >= 0) {
			fd = cached_fd;
			can_try_uncached = 1;
			debug_high("%d/psinfo, trying cached fd %d\n",
			    (int)pid, fd);
		} else {
			char pathbuf[PROC_PATH_MAX];

			can_try_uncached = 0;
			(void) snprintf(pathbuf, sizeof (pathbuf),
			    "/proc/%d/psinfo", (int)pid);
			if ((fd = rfd_open(pathbuf, 1, RFD_PSINFO,
			    revoke_psinfo, lpc, O_RDONLY, 0000)) < 0) {
				debug("cannot open %s", pathbuf);
				break;
			} else
				debug_high("opened %s, fd %d\n", pathbuf, fd);
		}

		if (pread(fd, psinfo, sizeof (*psinfo), 0) ==
		    sizeof (*psinfo) && psinfo->pr_pid == pid)
			break;
		else {
			debug_high("closed fd %d\n", fd);
			if (rfd_close(fd) != 0)
				debug("could not close fd %d", fd);
			fd = cached_fd = -1;
		}
	} while (can_try_uncached == 1);

	if (fd_update_cb == NULL || fd_update_cb(arg, fd) != 0)
		if (fd >= 0) {
			debug_high("closed %s fd %d\n", fd_update_cb == NULL ?
			    "uncached" : "cached", fd);
			if (rfd_close(fd) != 0)
				debug("could not close fd %d", fd);
		}

	debug_high("get_psinfo ret %d, fd %d, %s\n", ((fd >= 0) ? 0 : -1), fd,
	    fd_update_cb != NULL ? "cached" : "uncached");
	return ((fd >= 0) ? 0 : -1);
}

/*
 * Retrieve the collection membership of all processes and update the psinfo of
 * those non-system, non-zombie ones in collections.  For global zone processes,
 * we first attempt to put the process into a capped project collection.  We
 * also want to track the process for the global zone collection as a whole.
 */
static void
proc_cb(const pid_t pid)
{
	psinfo_t psinfo;

	if (get_psinfo(pid, &psinfo, -1, NULL, NULL, NULL) == 0) {
		lprocess_insert_mark(&psinfo);
		if (gz_capped && psinfo.pr_zoneid == GLOBAL_ZONEID) {
			/*
			 * We also want to track this process for the global
			 * zone as a whole so add it to the global zone
			 * collection as well.
			 */
			psinfo.pr_projid = -1;
			lprocess_insert_mark(&psinfo);
		}
	}
}

/*
 * Cache the process' psinfo fd, taking responsibility for freeing it.
 */
int
lprocess_update_psinfo_fd_cb(void *arg, int fd)
{
	lprocess_t *lpc = arg;

	lpc->lpc_psinfo_fd = fd;
	return (0);
}

/*
 * Get the system pagesize.
 */
static void
get_page_size(void)
{
	page_size_kb = sysconf(_SC_PAGESIZE) / 1024;
	debug("physical page size: %luKB\n", page_size_kb);
}

static void
tm_fmt(char *msg, hrtime_t t1, hrtime_t t2)
{
	hrtime_t diff = t2 - t1;

	if (diff < MILLISEC)
		debug("%s: %lld nanoseconds\n", msg, diff);
	else if (diff < MICROSEC)
		debug("%s: %.2f microseconds\n", msg, (float)diff / MILLISEC);
	else if (diff < NANOSEC)
		debug("%s: %.2f milliseconds\n", msg, (float)diff / MICROSEC);
	else
		debug("%s: %.2f seconds\n", msg, (float)diff / NANOSEC);
}

/*
 * Get the zone's & project's RSS from the kernel.
 */
static void
rss_sample(boolean_t my_zone_only, uint_t col_types)
{
	size_t nres;
	size_t i;
	uint_t flags;
	hrtime_t t1, t2;

	if (my_zone_only) {
		flags = VMUSAGE_ZONE;
	} else {
		flags = 0;
		if (col_types & CAPPED_PROJECT)
			flags |= VMUSAGE_PROJECTS;
		if (col_types & CAPPED_ZONE && my_zoneid == GLOBAL_ZONEID)
			flags |= VMUSAGE_ALL_ZONES;
	}

	debug("vmusage sample flags 0x%x\n", flags);
	if (flags == 0)
		return;

again:
	/* try the current buffer to see if the list will fit */
	nres = vmu_vals_len;
	t1 = gethrtime();
	if (getvmusage(flags, my_zone_only ? 0 : rcfg.rcfg_rss_sample_interval,
	    vmu_vals, &nres) != 0) {
		if (errno != EOVERFLOW) {
			warn(gettext("can't read RSS from kernel\n"));
			return;
		}
	}
	t2 = gethrtime();
	tm_fmt("getvmusage time", t1, t2);

	debug("kernel nres %lu\n", (ulong_t)nres);

	if (nres > vmu_vals_len) {
		/* array size is now too small, increase it and try again */
		free(vmu_vals);

		if ((vmu_vals = (vmusage_t *)calloc(nres,
		    sizeof (vmusage_t))) == NULL) {
			warn(gettext("out of memory: could not read RSS from "
			    "kernel\n"));
			vmu_vals_len = nvmu_vals = 0;
			return;
		}
		vmu_vals_len = nres;
		goto again;
	}

	nvmu_vals = nres;

	debug("vmusage_sample\n");
	for (i = 0; i < nvmu_vals; i++) {
		debug("%d: id: %d, type: 0x%x, rss_all: %llu (%lluKB), "
		    "swap: %llu\n", (int)i, (int)vmu_vals[i].vmu_id,
		    vmu_vals[i].vmu_type,
		    (unsigned long long)vmu_vals[i].vmu_rss_all,
		    (unsigned long long)vmu_vals[i].vmu_rss_all / 1024,
		    (unsigned long long)vmu_vals[i].vmu_swap_all);
	}
}

static void
update_col_rss(lcollection_t *lcol)
{
	int i;

	lcol->lcol_rss = 0;
	lcol->lcol_image_size = 0;

	for (i = 0; i < nvmu_vals; i++) {
		if (vmu_vals[i].vmu_id != lcol->lcol_id.rcid_val)
			continue;

		if (vmu_vals[i].vmu_type == VMUSAGE_ZONE &&
		    lcol->lcol_id.rcid_type != RCIDT_ZONE)
			continue;

		if (vmu_vals[i].vmu_type == VMUSAGE_PROJECTS &&
		    lcol->lcol_id.rcid_type != RCIDT_PROJECT)
			continue;

		/* we found the right RSS entry, update the collection vals */
		lcol->lcol_rss = vmu_vals[i].vmu_rss_all / 1024;
		lcol->lcol_image_size = vmu_vals[i].vmu_swap_all / 1024;
		break;
	}
}

/*
 * Sample the collection RSS, updating the collection's statistics with the
 * results.  Also, sum the rss of all capped projects & return true if
 * the collection is over cap.
 */
static int
rss_sample_col_cb(lcollection_t *lcol, void *arg)
{
	int64_t excess;
	uint64_t rss;
	sample_col_arg_t *col_argp = (sample_col_arg_t *)arg;

	update_col_rss(lcol);

	lcol->lcol_stat.lcols_rss_sample++;
	rss = lcol->lcol_rss;
	excess = rss - lcol->lcol_rss_cap;
	if (excess > 0) {
		lcol->lcol_stat.lcols_rss_act_sum += rss;
		col_argp->sca_any_over_cap = B_TRUE;
		if (lcol->lcol_id.rcid_type == RCIDT_PROJECT)
			col_argp->sca_project_over_cap = B_TRUE;
	}
	lcol->lcol_stat.lcols_rss_sum += rss;

	if (lcol->lcol_stat.lcols_min_rss > rss)
		lcol->lcol_stat.lcols_min_rss = rss;
	if (lcol->lcol_stat.lcols_max_rss < rss)
		lcol->lcol_stat.lcols_max_rss = rss;

	return (0);
}

/*
 * Determine if we have capped projects, capped zones or both.
 */
static int
col_type_cb(lcollection_t *lcol, void *arg)
{
	uint_t *col_type = (uint_t *)arg;

	/* skip uncapped collections */
	if (lcol->lcol_rss_cap == 0)
		return (1);

	if (lcol->lcol_id.rcid_type == RCIDT_PROJECT)
		*col_type |= CAPPED_PROJECT;
	else
		*col_type |= CAPPED_ZONE;

	/* once we know everything is capped, we can stop looking */
	if ((*col_type & CAPPED_ZONE) && (*col_type & CAPPED_PROJECT))
		return (1);

	return (0);
}

/*
 * Open /proc and walk entries.
 */
static void
proc_walk_all(void (*cb)(const pid_t))
{
	DIR *pdir;
	struct dirent *dirent;
	pid_t pid;

	(void) rfd_reserve(1);
	if ((pdir = opendir("/proc")) == NULL)
		die(gettext("couldn't open /proc!"));

	while ((dirent = readdir(pdir)) != NULL) {
		if (strcmp(".", dirent->d_name) == 0 ||
		    strcmp("..", dirent->d_name) == 0)
			continue;
		pid = atoi(dirent->d_name);
		ASSERT(pid != 0 || strcmp(dirent->d_name, "0") == 0);
		if (pid == rcapd_pid)
			continue;
		else
			cb(pid);
	}
	(void) closedir(pdir);
}

/*
 * Clear unmarked callback.
 */
/*ARGSUSED*/
static int
sweep_process_cb(lcollection_t *lcol, lprocess_t *lpc)
{
	if (lpc->lpc_mark) {
		lpc->lpc_mark = 0;
	} else {
		debug("process %d finished\n", (int)lpc->lpc_pid);
		lprocess_free(lpc);
	}

	return (0);
}

/*
 * Print, for debugging purposes, a collection's recently-sampled RSS and
 * excess.
 */
/*ARGSUSED*/
static int
excess_print_cb(lcollection_t *lcol, void *arg)
{
	int64_t excess = lcol->lcol_rss - lcol->lcol_rss_cap;

	debug("%s %s rss/cap: %llu/%llu, excess = %lld kB\n",
	    (lcol->lcol_id.rcid_type == RCIDT_PROJECT ? "project" : "zone"),
	    lcol->lcol_name,
	    (unsigned long long)lcol->lcol_rss,
	    (unsigned long long)lcol->lcol_rss_cap,
	    (long long)excess);

	return (0);
}

/*
 * Scan those collections which have exceeded their caps.
 *
 * If we're running in the global zone it might have a cap.  We don't want to
 * do any capping for the global zone yet since we might get under the cap by
 * just capping the projects in the global zone.
 */
/*ARGSUSED*/
static int
scan_cb(lcollection_t *lcol, void *arg)
{
	int64_t excess;

	/* skip over global zone collection for now but keep track for later */
	if (lcol->lcol_id.rcid_type == RCIDT_ZONE &&
	    lcol->lcol_id.rcid_val == GLOBAL_ZONEID) {
		gz_col = lcol;
		return (0);
	}

	if ((excess = lcol->lcol_rss - lcol->lcol_rss_cap) > 0) {
		scan(lcol, excess);
		lcol->lcol_stat.lcols_scan++;
	}

	return (0);
}

/*
 * Scan the global zone collection and see if it still exceeds its cap.
 * We take into account the effects of capping any global zone projects here.
 */
static void
scan_gz(lcollection_t *lcol, boolean_t project_over_cap)
{
	int64_t excess;

	/*
	 * If we had projects over their cap and the global zone was also over
	 * its cap then we need to get the up-to-date global zone rss to
	 * determine if we are still over the global zone cap.  We might have
	 * gone under while we scanned the capped projects.  If there were no
	 * projects over cap then we can use the rss value we already have for
	 * the global zone.
	 */
	excess = lcol->lcol_rss - lcol->lcol_rss_cap;
	if (project_over_cap && excess > 0) {
		rss_sample(B_TRUE, CAPPED_ZONE);
		update_col_rss(lcol);
		excess = lcol->lcol_rss - lcol->lcol_rss_cap;
	}

	if (excess > 0) {
		debug("global zone excess %lldKB\n", (long long)excess);
		scan(lcol, excess);
		lcol->lcol_stat.lcols_scan++;
	}
}

/*
 * Do a soft scan of those collections which have excesses.  A soft scan is one
 * in which the cap enforcement pressure is taken into account.  The difference
 * between the utilized physical memory and the cap enforcement pressure will
 * be scanned-for, and each collection will be scanned proportionally by their
 * present excesses.
 */
static int
soft_scan_cb(lcollection_t *lcol, void *a)
{
	int64_t excess;
	soft_scan_arg_t *arg = a;

	/* skip over global zone collection for now but keep track for later */
	if (lcol->lcol_id.rcid_type == RCIDT_ZONE &&
	    lcol->lcol_id.rcid_val == GLOBAL_ZONEID) {
		gz_col = lcol;
		return (0);
	}

	if ((excess = lcol->lcol_rss - lcol->lcol_rss_cap) > 0) {
		int64_t adjusted_excess =
		    excess * arg->ssa_scan_goal / arg->ssa_sum_excess;

		debug("%s %ld excess %lld scan_goal %lld sum_excess %llu, "
		    "scanning %lld\n",
		    (lcol->lcol_id.rcid_type == RCIDT_PROJECT ?
		    "project" : "zone"),
		    (long)lcol->lcol_id.rcid_val,
		    (long long)excess, (long long)arg->ssa_scan_goal,
		    (unsigned long long)arg->ssa_sum_excess,
		    (long long)adjusted_excess);

		scan(lcol, adjusted_excess);
		lcol->lcol_stat.lcols_scan++;
	}

	return (0);
}

static void
soft_scan_gz(lcollection_t *lcol, void *a)
{
	int64_t excess;
	soft_scan_arg_t *arg = a;

	/*
	 * If we had projects over their cap and the global zone was also over
	 * its cap then we need to get the up-to-date global zone rss to
	 * determine if we are still over the global zone cap.  We might have
	 * gone under while we scanned the capped projects.  If there were no
	 * projects over cap then we can use the rss value we already have for
	 * the global zone.
	 */
	excess = lcol->lcol_rss - lcol->lcol_rss_cap;
	if (arg->ssa_project_over_cap && excess > 0) {
		rss_sample(B_TRUE, CAPPED_ZONE);
		update_col_rss(lcol);
		excess = lcol->lcol_rss - lcol->lcol_rss_cap;
	}

	if (excess > 0) {
		int64_t adjusted_excess =
		    excess * arg->ssa_scan_goal / arg->ssa_sum_excess;

		debug("%s %ld excess %lld scan_goal %lld sum_excess %llu, "
		    "scanning %lld\n",
		    (lcol->lcol_id.rcid_type == RCIDT_PROJECT ?
		    "project" : "zone"),
		    (long)lcol->lcol_id.rcid_val,
		    (long long)excess, (long long)arg->ssa_scan_goal,
		    (unsigned long long)arg->ssa_sum_excess,
		    (long long)adjusted_excess);

		scan(lcol, adjusted_excess);
		lcol->lcol_stat.lcols_scan++;
	}
}

/*
 * When a scan could happen, but caps aren't enforced tick the
 * lcols_unenforced_cap counter.
 */
/*ARGSUSED*/
static int
unenforced_cap_cb(lcollection_t *lcol, void *arg)
{
	lcol->lcol_stat.lcols_unenforced_cap++;

	return (0);
}

/*
 * Update the count of physically installed memory.
 */
static void
update_phys_total(void)
{
	uint64_t old_phys_total;

	old_phys_total = phys_total;
	phys_total = (uint64_t)sysconf(_SC_PHYS_PAGES) * page_size_kb;
	if (phys_total != old_phys_total)
		debug("physical memory%s: %lluM\n", (old_phys_total == 0 ?
		    "" : " adjusted"), (unsigned long long)(phys_total / 1024));
}

/*
 * Unlink a process from its collection, updating relevant statistics, and
 * freeing its associated memory.
 */
void
lprocess_free(lprocess_t *lpc)
{
	pid_t pid;

	lpc->lpc_collection->lcol_stat.lcols_proc_out++;

	if (lpc->lpc_prev != NULL)
		lpc->lpc_prev->lpc_next = lpc->lpc_next;
	if (lpc->lpc_next != NULL)
		lpc->lpc_next->lpc_prev = lpc->lpc_prev;
	if (lpc->lpc_collection->lcol_lprocess == lpc)
		lpc->lpc_collection->lcol_lprocess = (lpc->lpc_next !=
		    lpc ? lpc->lpc_next : NULL);
	lpc->lpc_next = lpc->lpc_prev = NULL;

	if (lpc->lpc_prpageheader != NULL)
		free(lpc->lpc_prpageheader);
	if (lpc->lpc_xmap != NULL)
		free(lpc->lpc_xmap);
	if (lpc->lpc_psinfo_fd >= 0) {
		if (rfd_close(lpc->lpc_psinfo_fd) != 0)
			debug("could not close %d lpc_psinfo_fd %d",
			    (int)lpc->lpc_pid, lpc->lpc_psinfo_fd);
		lpc->lpc_psinfo_fd = -1;
	}
	if (lpc->lpc_pgdata_fd >= 0) {
		if (rfd_close(lpc->lpc_pgdata_fd) != 0)
			debug("could not close %d lpc_pgdata_fd %d",
			    (int)lpc->lpc_pid, lpc->lpc_pgdata_fd);
		lpc->lpc_pgdata_fd = -1;
	}
	if (lpc->lpc_xmap_fd >= 0) {
		if (rfd_close(lpc->lpc_xmap_fd) != 0)
			debug("could not close %d lpc_xmap_fd %d",
			    (int)lpc->lpc_pid, lpc->lpc_xmap_fd);
		lpc->lpc_xmap_fd = -1;
	}
	if (lpc->lpc_ignore != NULL)
		lmapping_free(&lpc->lpc_ignore);
	pid = lpc->lpc_pid;
	free(lpc);
	debug_high("process %d freed\n", (int)pid);
}

/*
 * Collection clear callback.
 */
/*ARGSUSED*/
static int
collection_clear_cb(lcollection_t *lcol, void *arg)
{
	lcol->lcol_mark = 0;

	return (0);
}

/*
 * Respond to a terminating signal by setting a termination flag.
 */
/*ARGSUSED*/
static void
terminate_signal(int signal)
{
	if (termination_signal == 0)
		termination_signal = signal;
	should_run = 0;
}

/*
 * Handle any synchronous or asynchronous signals that would ordinarily cause a
 * process to abort.
 */
/*ARGSUSED*/
static void
abort_signal(int signal)
{
	/*
	 * Allow the scanner to make a last-ditch effort to resume any stopped
	 * processes.
	 */
	scan_abort();
	abort();
}

/*
 * Clean up collections which have been removed due to configuration.  Unlink
 * the collection from lcollection and free it.
 */
/*ARGSUSED*/
static int
collection_sweep_cb(lcollection_t *lcol, void *arg)
{
	if (lcol->lcol_mark == 0) {
		debug("freeing %s %s\n",
		    (lcol->lcol_id.rcid_type == RCIDT_PROJECT ?
		    "project" : "zone"), lcol->lcol_name);
		lcollection_free(lcol);
	}

	return (0);
}

/*
 * Set those variables which depend on the global configuration.
 */
static void
finish_configuration(void)
{
	/*
	 * Warn that any lnode (or non-project) mode specification (by an SRM
	 * 1.3 configuration file, for example) is ignored.
	 */
	if (strcmp(rcfg.rcfg_mode_name, "project") != 0) {
		warn(gettext("%s mode specification ignored -- using project"
		    " mode\n"), rcfg.rcfg_mode_name);
		rcfg.rcfg_mode_name = "project";
		rcfg.rcfg_mode = rctype_project;
	}
}

/*
 * Cause the configuration to be reread and applied.
 */
static void
reread_configuration(void)
{
	rcfg_t rcfg_new;

	if (rcfg_read(&rcfg_new, update_statistics) != E_SUCCESS) {
		warn(gettext("can't reread configuration \n"));
		exit(SMF_EXIT_ERR_CONFIG);
	} else {
		/*
		 * Done reading configuration.  Remove existing
		 * collections in case there is a change in collection type.
		 */
		if (rcfg.rcfg_mode != rcfg_new.rcfg_mode) {
			list_walk_collection(collection_clear_cb, NULL);
			list_walk_collection(collection_sweep_cb, NULL);
		}

		/*
		 * Make the newly-read configuration the global one, and update
		 * any variables that depend on it.
		 */
		rcfg = rcfg_new;
		finish_configuration();
	}
}

/*
 * First, examine changes, additions, and deletions to cap definitions.
 * Then, set the next event time.
 */
static void
reconfigure(hrtime_t now, hrtime_t *next_configuration,
    hrtime_t *next_proc_walk, hrtime_t *next_rss_sample)
{
	debug("reconfigure...\n");

	/*
	 * Walk the lcollection, marking active collections so inactive ones
	 * can be freed.
	 */
	list_walk_collection(collection_clear_cb, NULL);
	lcollection_update(LCU_ACTIVE_ONLY); /* mark */
	list_walk_collection(collection_sweep_cb, NULL);

	*next_configuration = NEXT_EVENT_TIME(now,
	    rcfg.rcfg_reconfiguration_interval);

	/*
	 * Reset each event time to the shorter of the previous and new
	 * intervals.
	 */
	if (next_report == 0 && rcfg.rcfg_report_interval > 0)
		next_report = now;
	else
		next_report = POSITIVE_MIN(next_report,
		    NEXT_REPORT_EVENT_TIME(now, rcfg.rcfg_report_interval));

	if (*next_proc_walk == 0 && rcfg.rcfg_proc_walk_interval > 0)
		*next_proc_walk = now;
	else
		*next_proc_walk = POSITIVE_MIN(*next_proc_walk,
		    NEXT_EVENT_TIME(now, rcfg.rcfg_proc_walk_interval));

	if (*next_rss_sample == 0 && rcfg.rcfg_rss_sample_interval > 0)
		*next_rss_sample = now;
	else
		*next_rss_sample = POSITIVE_MIN(*next_rss_sample,
		    NEXT_EVENT_TIME(now, rcfg.rcfg_rss_sample_interval));
}

/*
 * Respond to SIGHUP by triggering the rereading the configuration and cap
 * definitions.
 */
/*ARGSUSED*/
static void
sighup(int signal)
{
	should_reconfigure = 1;
}

/*
 * Print, for debugging purposes, each collection's interval statistics.
 */
/*ARGSUSED*/
static int
simple_report_collection_cb(lcollection_t *lcol, void *arg)
{
#define	DELTA(field) \
	(unsigned long long)( \
	    (lcol->lcol_stat.field - lcol->lcol_stat_old.field))

	debug("%s %s status: succeeded/attempted (k): %llu/%llu, "
	    "ineffective/scans/unenforced/samplings:  %llu/%llu/%llu/%llu, RSS "
	    "min/max (k): %llu/%llu, cap %llu kB, processes/thpt: %llu/%llu, "
	    "%llu scans over %llu ms\n",
	    (lcol->lcol_id.rcid_type == RCIDT_PROJECT ? "project" : "zone"),
	    lcol->lcol_name,
	    DELTA(lcols_pg_eff), DELTA(lcols_pg_att),
	    DELTA(lcols_scan_ineffective), DELTA(lcols_scan),
	    DELTA(lcols_unenforced_cap), DELTA(lcols_rss_sample),
	    (unsigned long long)lcol->lcol_stat.lcols_min_rss,
	    (unsigned long long)lcol->lcol_stat.lcols_max_rss,
	    (unsigned long long)lcol->lcol_rss_cap,
	    (unsigned long long)(lcol->lcol_stat.lcols_proc_in -
	    lcol->lcol_stat.lcols_proc_out), DELTA(lcols_proc_out),
	    DELTA(lcols_scan_count),
	    NSEC2MSEC(DELTA(lcols_scan_time_complete)));

#undef DELTA

	return (0);
}

/*
 * Record each collection's interval statistics in the statistics file.
 */
static int
report_collection_cb(lcollection_t *lcol, void *arg)
{
	lcollection_report_t dc;
	int fd = (intptr_t)arg;

	/*
	 * Copy the relevant fields to the collection's record.
	 */
	bzero(&dc, sizeof (dc));
	dc.lcol_id = lcol->lcol_id;
	(void) strcpy(dc.lcol_name, lcol->lcol_name);
	dc.lcol_rss = lcol->lcol_rss;
	dc.lcol_image_size = lcol->lcol_image_size;
	dc.lcol_rss_cap = lcol->lcol_rss_cap;
	dc.lcol_stat = lcol->lcol_stat;

	if (write(fd, &dc, sizeof (dc)) == sizeof (dc)) {
		lcol->lcol_stat_old = lcol->lcol_stat;
	} else {
		debug("can't write %s %s statistics",
		    (lcol->lcol_id.rcid_type == RCIDT_PROJECT ?
		    "project" : "zone"),
		    lcol->lcol_name);
	}

	return (0);
}

/*
 * Determine the count of pages scanned by the global page scanner, obtained
 * from the cpu_stat:*::scan kstats.  Return zero on success.
 */
static int
get_globally_scanned_pages(uint64_t *scannedp)
{
	kstat_t *ksp;
	uint64_t scanned = 0;

	if (kstat_chain_update(kctl) == -1) {
		warn(gettext("can't update kstat chain"));
		return (0);
	}

	for (ksp = kctl->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
		if (strcmp(ksp->ks_module, "cpu_stat") == 0) {
			if (kstat_read(kctl, ksp, NULL) != -1) {
				scanned += ((cpu_stat_t *)
				    ksp->ks_data)->cpu_vminfo.scan;
			} else {
				return (-1);
			}
		}
	}

	*scannedp = scanned;
	return (0);
}

/*
 * Determine if the global page scanner is running, during which no memory
 * caps should be enforced, to prevent interference with the global page
 * scanner.
 */
static boolean_t
is_global_scanner_running()
{
	/* measure delta in page scan count */
	static uint64_t new_sp = 0;
	static uint64_t old_sp = 0;
	boolean_t res = B_FALSE;

	if (get_globally_scanned_pages(&new_sp) == 0) {
		if (old_sp != 0 && (new_sp - old_sp) > 0) {
			debug("global memory pressure detected (%llu "
			    "pages scanned since last interval)\n",
			    (unsigned long long)(new_sp - old_sp));
			res = B_TRUE;
		}
		old_sp = new_sp;
	} else {
		warn(gettext("unable to read cpu statistics"));
		new_sp = old_sp;
	}

	return (res);
}

/*
 * If soft caps are in use, determine if global memory pressure exceeds the
 * configured maximum above which soft caps are enforced.
 */
static boolean_t
must_enforce_soft_caps()
{
	/*
	 * Check for changes to the amount of installed physical memory, to
	 * compute the current memory pressure.
	 */
	update_phys_total();

	memory_pressure = 100 - (int)((sysconf(_SC_AVPHYS_PAGES) * page_size_kb)
	    * 100.0 / phys_total);
	memory_pressure_sample++;
	if (rcfg.rcfg_memory_cap_enforcement_pressure > 0 &&
	    memory_pressure > rcfg.rcfg_memory_cap_enforcement_pressure) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Update the shared statistics file with each collection's current statistics.
 * Return zero on success.
 */
static int
update_statistics(void)
{
	int fd, res;
	static char template[LINELEN];

	/*
	 * Try to create a directory irrespective of whether it is existing
	 * or not. If it is not there then it will create. Otherwise any way
	 * it will fail at mkstemp call below.
	 */
	(void) mkdir(STAT_FILE_DIR, 0755);

	/*
	 * Create a temporary file.
	 */
	if (sizeof (template) < (strlen(rcfg.rcfg_stat_file) +
	    strlen(STAT_TEMPLATE_SUFFIX) + 1)) {
		debug("temporary file template size too small\n");
		return (-1);
	}
	(void) strcpy(template, rcfg.rcfg_stat_file);
	(void) strcat(template, STAT_TEMPLATE_SUFFIX);
	(void) rfd_reserve(1);
	fd = mkstemp(template);

	/*
	 * Write the header and per-collection statistics.
	 */
	if (fd >= 0) {
		rcapd_stat_hdr_t rs;

		rs.rs_pid = rcapd_pid;
		rs.rs_time = gethrtime();
		ASSERT(sizeof (rs.rs_mode) > strlen(rcfg.rcfg_mode_name));
		(void) strcpy(rs.rs_mode, rcfg.rcfg_mode_name);
		rs.rs_pressure_cur = memory_pressure;
		rs.rs_pressure_cap = rcfg.rcfg_memory_cap_enforcement_pressure;
		rs.rs_pressure_sample = memory_pressure_sample;

		if (fchmod(fd, 0644) == 0 && write(fd, &rs, sizeof (rs)) ==
		    sizeof (rs)) {
			list_walk_collection(report_collection_cb,
			    (void *)(intptr_t)fd);
			/*
			 * Replace the existing statistics file with this new
			 * one.
			 */
			res = rename(template, rcfg.rcfg_stat_file);
		} else
			res = -1;
		(void) close(fd);
	} else
		res = -1;

	return (res);
}

/*
 * Verify the statistics file can be created and written to, and die if an
 * existing file may be in use by another rcapd.
 */
static int
verify_statistics(void)
{
	pid_t pid;

	/*
	 * Warn if another instance of rcapd might be active.
	 */
	(void) rfd_reserve(1);
	pid = stat_get_rcapd_pid(rcfg.rcfg_stat_file);
	if (pid != rcapd_pid && pid != -1)
		die(gettext("%s exists; rcapd may already be active\n"),
		    rcfg.rcfg_stat_file);

	return (update_statistics());
}

static int
sum_excess_cb(lcollection_t *lcol, void *arg)
{
	uint64_t *sum_excess = arg;

	*sum_excess += MAX((int64_t)0, (int64_t)(lcol->lcol_rss -
	    lcol->lcol_rss_cap));
	return (0);
}

/*
 * Compute the quantity of memory (in kilobytes) above the cap enforcement
 * pressure.  Set the scan goal to that quantity (or at most the excess).
 */
static void
compute_soft_scan_goal(soft_scan_arg_t *argp)
{
	/*
	 * Compute the sum of the collections' excesses, which will be the
	 * denominator.
	 */
	argp->ssa_sum_excess = 0;
	list_walk_collection(sum_excess_cb, &(argp->ssa_sum_excess));

	argp->ssa_scan_goal = MIN((sysconf(_SC_PHYS_PAGES) *
	    (100 - rcfg.rcfg_memory_cap_enforcement_pressure) / 100 -
	    sysconf(_SC_AVPHYS_PAGES)) * page_size_kb,
	    argp->ssa_sum_excess);
}

static void
rcapd_usage(void)
{
	info(gettext("usage: rcapd [-d]\n"));
}

void
check_update_statistics(void)
{
	hrtime_t now = gethrtime();

	if (EVENT_TIME(now, next_report)) {
		debug("updating statistics...\n");
		list_walk_collection(simple_report_collection_cb, NULL);
		if (update_statistics() != 0)
			debug("couldn't update statistics");
		next_report = NEXT_REPORT_EVENT_TIME(now,
		    rcfg.rcfg_report_interval);
	}
}

static void
verify_and_set_privileges(void)
{
	priv_set_t *required =
	    priv_str_to_set("zone,sys_resource,proc_owner", ",", NULL);

	/*
	 * Ensure the required privileges, suitable for controlling processes,
	 * are possessed.
	 */
	if (setppriv(PRIV_SET, PRIV_PERMITTED, required) != 0 || setppriv(
	    PRIV_SET, PRIV_EFFECTIVE, required) != 0)
		die(gettext("can't set requisite privileges"));

	/*
	 * Ensure access to /var/run/daemon.
	 */
	if (setreuid(DAEMON_UID, DAEMON_UID) != 0)
		die(gettext("cannot become user daemon"));

	priv_freeset(required);
}

/*
 * This function does the top-level work to determine if we should do any
 * memory capping, and if so, it invokes the right call-backs to do the work.
 */
static void
do_capping(hrtime_t now, hrtime_t *next_proc_walk)
{
	boolean_t enforce_caps;
	/* soft cap enforcement flag, depending on memory pressure */
	boolean_t enforce_soft_caps;
	/* avoid interference with kernel's page scanner */
	boolean_t global_scanner_running;
	sample_col_arg_t col_arg;
	soft_scan_arg_t arg;
	uint_t col_types = 0;

	/* check what kind of collections (project/zone) are capped */
	list_walk_collection(col_type_cb, &col_types);
	debug("collection types: 0x%x\n", col_types);

	/* no capped collections, skip checking rss */
	if (col_types == 0)
		return;

	/* Determine if soft caps are enforced. */
	enforce_soft_caps = must_enforce_soft_caps();

	/* Determine if the global page scanner is running. */
	global_scanner_running = is_global_scanner_running();

	/*
	 * Sample collections' member processes RSSes and recompute
	 * collections' excess.
	 */
	rss_sample(B_FALSE, col_types);

	col_arg.sca_any_over_cap = B_FALSE;
	col_arg.sca_project_over_cap = B_FALSE;
	list_walk_collection(rss_sample_col_cb, &col_arg);
	list_walk_collection(excess_print_cb, NULL);
	debug("any collection/project over cap = %d, %d\n",
	    col_arg.sca_any_over_cap, col_arg.sca_project_over_cap);

	if (enforce_soft_caps)
		debug("memory pressure %d%%\n", memory_pressure);

	/*
	 * Cap enforcement is determined by the previous conditions.
	 */
	enforce_caps = !global_scanner_running && col_arg.sca_any_over_cap &&
	    (rcfg.rcfg_memory_cap_enforcement_pressure == 0 ||
	    enforce_soft_caps);

	debug("%senforcing caps\n", enforce_caps ? "" : "not ");

	/*
	 * If soft caps are in use, determine the size of the portion from each
	 * collection to scan for.
	 */
	if (enforce_caps && enforce_soft_caps)
		compute_soft_scan_goal(&arg);

	/*
	 * Victimize offending collections.
	 */
	if (enforce_caps && (!enforce_soft_caps ||
	    (arg.ssa_scan_goal > 0 && arg.ssa_sum_excess > 0))) {

		/*
		 * Since at least one collection is over its cap & needs
		 * enforcing, check if it is at least time for a process walk
		 * (we could be well past time since we only walk /proc when
		 * we need to) and if so, update each collections process list
		 * in a single pass through /proc.
		 */
		if (EVENT_TIME(now, *next_proc_walk)) {
			debug("scanning process list...\n");
			proc_walk_all(proc_cb);		 /* insert & mark */
			list_walk_all(sweep_process_cb); /* free dead procs */
			*next_proc_walk = NEXT_EVENT_TIME(now,
			    rcfg.rcfg_proc_walk_interval);
		}

		gz_col = NULL;
		if (enforce_soft_caps) {
			debug("scan goal is %lldKB\n",
			    (long long)arg.ssa_scan_goal);
			list_walk_collection(soft_scan_cb, &arg);
			if (gz_capped && gz_col != NULL) {
				/* process global zone */
				arg.ssa_project_over_cap =
				    col_arg.sca_project_over_cap;
				soft_scan_gz(gz_col, &arg);
			}
		} else {
			list_walk_collection(scan_cb, NULL);
			if (gz_capped && gz_col != NULL) {
				/* process global zone */
				scan_gz(gz_col, col_arg.sca_project_over_cap);
			}
		}
	} else if (col_arg.sca_any_over_cap) {
		list_walk_collection(unenforced_cap_cb, NULL);
	}
}

int
main(int argc, char *argv[])
{
	int res;
	int should_fork = 1;	/* fork flag */
	hrtime_t now;		/* current time */
	hrtime_t next;		/* time of next event */
	int sig;		/* signal iteration */
	struct rlimit rl;
	hrtime_t next_proc_walk;	/* time of next /proc scan */
	hrtime_t next_configuration;	/* time of next configuration */
	hrtime_t next_rss_sample;	/* (latest) time of next RSS sample */

	(void) set_message_priority(RCM_INFO);
	(void) setpname("rcapd");
	rcapd_pid = getpid();
	(void) chdir("/");
	should_run = 1;
	ever_ran = 0;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Parse command-line options.
	 */
	while ((res = getopt(argc, argv, "dF")) > 0)
		switch (res) {
		case 'd':
			should_fork = 0;
			if (debug_mode == 0) {
				debug_mode = 1;
				(void) set_message_priority(RCM_DEBUG);
			} else
				(void) set_message_priority(RCM_DEBUG_HIGH);
			break;
		case 'F':
			should_fork = 0;
			break;
		default:
			rcapd_usage();
			return (E_USAGE);
			/*NOTREACHED*/
		}

	/*
	 * Read the configuration.
	 */
	if (rcfg_read(&rcfg, verify_statistics) != E_SUCCESS) {
		warn(gettext("resource caps not configured\n"));
		return (SMF_EXIT_ERR_CONFIG);
	}

	/*
	 * If not debugging, fork and continue operating, changing the
	 * destination of messages to syslog().
	 */
	if (should_fork == 1) {
		pid_t child;
		debug("forking\n");
		child = fork();
		if (child == -1)
			die(gettext("cannot fork"));
		if (child > 0)
			return (0);
		else {
			rcapd_pid = getpid();
			(void) set_message_destination(RCD_SYSLOG);
			(void) fclose(stdin);
			(void) fclose(stdout);
			(void) fclose(stderr);
		}
		/*
		 * Start a new session and detatch from the controlling tty.
		 */
		if (setsid() == (pid_t)-1)
			debug(gettext("setsid() failed; cannot detach from "
			    "terminal"));
	}

	finish_configuration();
	should_reconfigure = 0;

	/*
	 * Check that required privileges are possessed.
	 */
	verify_and_set_privileges();

	now = next_report = next_proc_walk = next_rss_sample = gethrtime();
	next_configuration = NEXT_EVENT_TIME(gethrtime(),
	    rcfg.rcfg_reconfiguration_interval);

	/*
	 * Open the kstat chain.
	 */
	kctl = kstat_open();
	if (kctl == NULL)
		die(gettext("can't open kstats"));

	/*
	 * Set RLIMIT_NOFILE as high as practical, so roughly 10K processes can
	 * be effectively managed without revoking descriptors (at 3 per
	 * process).
	 */
	rl.rlim_cur = 32 * 1024;
	rl.rlim_max = 32 * 1024;
	if (setrlimit(RLIMIT_NOFILE, &rl) != 0 &&
	    getrlimit(RLIMIT_NOFILE, &rl) == 0) {
		rl.rlim_cur = rl.rlim_max;
		(void) setrlimit(RLIMIT_NOFILE, &rl);
	}
	(void) enable_extended_FILE_stdio(-1, -1);

	if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
		debug("fd limit: %lu\n", rl.rlim_cur);
	else
		debug("fd limit: unknown\n");

	get_page_size();
	my_zoneid = getzoneid();

	/*
	 * Handle those signals whose (default) exit disposition
	 * prevents rcapd from finishing scanning before terminating.
	 */
	(void) sigset(SIGINT, terminate_signal);
	(void) sigset(SIGQUIT, abort_signal);
	(void) sigset(SIGILL, abort_signal);
	(void) sigset(SIGEMT, abort_signal);
	(void) sigset(SIGFPE, abort_signal);
	(void) sigset(SIGBUS, abort_signal);
	(void) sigset(SIGSEGV, abort_signal);
	(void) sigset(SIGSYS, abort_signal);
	(void) sigset(SIGPIPE, terminate_signal);
	(void) sigset(SIGALRM, terminate_signal);
	(void) sigset(SIGTERM, terminate_signal);
	(void) sigset(SIGUSR1, terminate_signal);
	(void) sigset(SIGUSR2, terminate_signal);
	(void) sigset(SIGPOLL, terminate_signal);
	(void) sigset(SIGVTALRM, terminate_signal);
	(void) sigset(SIGXCPU, abort_signal);
	(void) sigset(SIGXFSZ, abort_signal);
	for (sig = SIGRTMIN; sig <= SIGRTMAX; sig++)
		(void) sigset(sig, terminate_signal);

	/*
	 * Install a signal handler for reconfiguration processing.
	 */
	(void) sigset(SIGHUP, sighup);

	/*
	 * Determine which process collections to cap.
	 */
	lcollection_update(LCU_COMPLETE);

	/*
	 * Loop forever, monitoring collections' resident set sizes and
	 * enforcing their caps.  Look for changes in caps as well as
	 * responding to requests to reread the configuration.  Update
	 * per-collection statistics periodically.
	 */
	while (should_run != 0) {
		struct timespec ts;

		/*
		 * Announce that rcapd is starting.
		 */
		if (ever_ran == 0) {
			info(gettext("starting\n"));
			ever_ran = 1;
		}

		/*
		 * Check the configuration at every next_configuration interval.
		 * Update the rss data once every next_rss_sample interval.
		 * The condition of global memory pressure is also checked at
		 * the same frequency, if strict caps are in use.
		 */
		now = gethrtime();

		/*
		 * Detect configuration and cap changes only when SIGHUP
		 * is received. Call reconfigure to apply new configuration
		 * parameters.
		 */
		if (should_reconfigure == 1) {
			reread_configuration();
			should_reconfigure = 0;
			reconfigure(now, &next_configuration, &next_proc_walk,
			    &next_rss_sample);
		}

		if (EVENT_TIME(now, next_configuration)) {
			reconfigure(now, &next_configuration, &next_proc_walk,
			    &next_rss_sample);
		}

		/*
		 * Do the main work for enforcing caps.
		 */
		if (EVENT_TIME(now, next_rss_sample)) {
			do_capping(now, &next_proc_walk);

			next_rss_sample = NEXT_EVENT_TIME(now,
			    rcfg.rcfg_rss_sample_interval);
		}

		/*
		 * Update the statistics file, if it's time.
		 */
		check_update_statistics();

		/*
		 * Sleep for some time before repeating.
		 */
		now = gethrtime();
		next = next_configuration;
		next = POSITIVE_MIN(next, next_report);
		next = POSITIVE_MIN(next, next_rss_sample);
		if (next > now && should_run != 0) {
			debug("sleeping %-4.2f seconds\n", (float)(next -
			    now) / (float)NANOSEC);
			hrt2ts(next - now, &ts);
			(void) nanosleep(&ts, NULL);
		}
	}
	if (termination_signal != 0)
		debug("exiting due to signal %d\n", termination_signal);
	if (ever_ran != 0)
		info(gettext("exiting\n"));

	/*
	 * Unlink the statistics file before exiting.
	 */
	if (rcfg.rcfg_stat_file[0] != 0)
		(void) unlink(rcfg.rcfg_stat_file);

	return (E_SUCCESS);
}
