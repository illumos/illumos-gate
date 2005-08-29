/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <stdlib.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <zone.h>
#include <assert.h>
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

typedef struct soft_scan_arg {
	uint64_t ssa_sum_excess;
	int64_t ssa_scan_goal;
} soft_scan_arg_t;

static int debug_mode = 0;		/* debug mode flag */
static pid_t rcapd_pid;			/* rcapd's pid to ensure it's not */
					/* scanned */
static kstat_ctl_t *kctl;		/* kstat chain */
static uint64_t new_sp = 0, old_sp = 0;	/* measure delta in page scan count */
static int enforce_caps = 0;		/* cap enforcement flag, dependent on */
					/* enforce_soft_caps and */
					/* global_scanner_running */
static int enforce_soft_caps = 0;	/* soft cap enforcement flag, */
					/* depending on memory pressure */
static int memory_pressure = 0;		/* physical memory utilization (%) */
static int memory_pressure_sample = 0;	/* count of samples */
static int global_scanner_running = 0;	/* global scanning flag, to avoid */
					/* interference with kernel's page */
					/* scanner */
static hrtime_t next_report;		/* time of next report */
static int termination_signal = 0;	/* terminating signal */

rcfg_t rcfg;

/*
 * Flags.
 */
static int ever_ran;
int should_run;
static int should_reconfigure;

static int verify_statistics(void);
static int update_statistics(void);

/*
 * Checks if a process is marked 'system'.  Returns zero only when it is not.
 */
static int
proc_issystem(pid_t pid)
{
	char pc_clname[PC_CLNMSZ];

	if (priocntl(P_PID, pid, PC_GETXPARMS, NULL, PC_KY_CLNAME, pc_clname,
	    PC_KY_NULL) != -1) {
		return (strcmp(pc_clname, "SYS") == 0);
	} else {
		debug("cannot get class-specific scheduling parameters; "
		    "assuming system process");
		return (-1);
	}
}

/*
 * fname is the process name, for debugging messages, and unscannable is a flag
 * indicating whether the process should be scanned.
 */
static void
lprocess_insert_mark(pid_t pid, id_t colid, char *fname, int unscannable)
{
	lcollection_t *lcol;
	lprocess_t *lproc;

	if ((lcol = lcollection_find(colid)) == NULL)
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
			    "including me, %d!\n", (long long)lcol->lcol_id,
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

		debug("tracking %d %d %s%s\n", (int)colid, (int)pid, fname,
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
 * Retrieve the collection membership of all processes in our zone, and update
 * the psinfo of those non-system, non-zombie ones in collections.
 */
static void
proc_cb(const pid_t pid)
{
	static zoneid_t ours = (zoneid_t)-1;
	psinfo_t psinfo;

	if (ours == (zoneid_t)-1)
		ours = getzoneid();

	if (get_psinfo(pid, &psinfo, -1, NULL, NULL, NULL) == 0 &&
	    psinfo.pr_zoneid == ours)
		lprocess_insert_mark(psinfo.pr_pid, rc_getidbypsinfo(&psinfo),
		    psinfo.pr_psargs, psinfo.pr_nlwp == 0);
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
 * Update the RSS of processes in monitored collections.
 */
/*ARGSUSED*/
static int
mem_sample_cb(lcollection_t *lcol, lprocess_t *lpc)
{
	psinfo_t psinfo;

	if (get_psinfo(lpc->lpc_pid, &psinfo, lpc->lpc_psinfo_fd,
	    lprocess_update_psinfo_fd_cb, lpc, lpc) == 0) {
		lpc->lpc_rss = psinfo.pr_rssize;
		lpc->lpc_size = psinfo.pr_size;
	} else {
		if (errno == ENOENT)
			debug("process %d finished\n", (int)lpc->lpc_pid);
		else
			debug("process %d: cannot read psinfo",
			    (int)lpc->lpc_pid);
		lprocess_free(lpc);
	}

	return (0);
}

/*
 * Sample the collection RSS, updating the collection's statistics with the
 * results.
 */
/*ARGSUSED*/
static int
rss_sample_col_cb(lcollection_t *lcol, void *arg)
{
	int64_t excess;
	uint64_t rss;

	/*
	 * If updating statistics for a new interval, reset the affected
	 * counters.
	 */
	if (lcol->lcol_stat_invalidate != 0) {
		lcol->lcol_stat_old = lcol->lcol_stat;
		lcol->lcol_stat.lcols_min_rss = (int64_t)-1;
		lcol->lcol_stat.lcols_max_rss = 0;
		lcol->lcol_stat_invalidate = 0;
	}

	lcol->lcol_stat.lcols_rss_sample++;
	excess = lcol->lcol_rss - lcol->lcol_rss_cap;
	rss = lcol->lcol_rss;
	if (excess > 0)
		lcol->lcol_stat.lcols_rss_act_sum += rss;
	lcol->lcol_stat.lcols_rss_sum += rss;

	if (lcol->lcol_stat.lcols_min_rss > rss)
		lcol->lcol_stat.lcols_min_rss = rss;
	if (lcol->lcol_stat.lcols_max_rss < rss)
		lcol->lcol_stat.lcols_max_rss = rss;

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
 * Memory update callback.
 */
static int
memory_all_cb(lcollection_t *lcol, lprocess_t *lpc)
{
	debug_high("%s %s, pid %d: rss += %llu/%llu\n", rcfg.rcfg_mode_name,
	    lcol->lcol_name, (int)lpc->lpc_pid,
	    (unsigned long long)lpc->lpc_rss,
	    (unsigned long long)lpc->lpc_size);
	ASSERT(lpc->lpc_rss <= lpc->lpc_size);
	lcol->lcol_rss += lpc->lpc_rss;
	lcol->lcol_image_size += lpc->lpc_size;

	return (0);
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
 * Memory clear callback.
 */
/*ARGSUSED*/
static int
collection_zero_mem_cb(lcollection_t *lcol, void *arg)
{
	lcol->lcol_rss = 0;
	lcol->lcol_image_size = 0;

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
	    rcfg.rcfg_mode_name, lcol->lcol_name,
	    (unsigned long long)lcol->lcol_rss,
	    (unsigned long long)lcol->lcol_rss_cap,
	    (long long)excess);

	return (0);
}

/*
 * Scan those collections which have exceeded their caps.
 */
/*ARGSUSED*/
static int
scan_cb(lcollection_t *lcol, void *arg)
{
	int64_t excess;

	if ((excess = lcol->lcol_rss - lcol->lcol_rss_cap) > 0) {
		scan(lcol, excess);
		lcol->lcol_stat.lcols_scan++;
	}

	return (0);
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

	if ((excess = lcol->lcol_rss - lcol->lcol_rss_cap) > 0) {
		debug("col %lld excess %lld scan_goal %lld sum_excess %llu, "
		    "scanning %lld\n", (long long)lcol->lcol_id,
		    (long long)excess, (long long)arg->ssa_scan_goal,
		    (unsigned long long)arg->ssa_sum_excess,
		    (long long)(excess * arg->ssa_scan_goal /
		    arg->ssa_sum_excess));

		scan(lcol, (int64_t)(excess * arg->ssa_scan_goal /
		    arg->ssa_sum_excess));
		lcol->lcol_stat.lcols_scan++;
	}

	return (0);
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
	phys_total = (uint64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE)
	    / 1024;
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
		debug("freeing %s %s\n", rcfg.rcfg_mode_name, lcol->lcol_name);
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

	lcollection_set_type(rcfg.rcfg_mode);
}

/*
 * Cause the configuration file to be reread and applied.
 */
static void
reread_configuration_file(void)
{
	rcfg_t rcfg_new;
	struct stat st;

	if (stat(rcfg.rcfg_filename, &st) == 0 && st.st_mtime ==
	    rcfg.rcfg_last_modification)
		return;

	if (rcfg_read(rcfg.rcfg_filename, rcfg.rcfg_fd, &rcfg_new,
	    update_statistics) != 0)
		warn(gettext("can't reread configuration"));
	else {
		/*
		 * The configuration file has been read.  Remove existing
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
 * Reread the configuration filex, then examine changes, additions, and
 * deletions to cap definitions.
 */
static void
reconfigure(void)
{
	debug("reconfigure...\n");

	/*
	 * Reread the configuration data.
	 */
	reread_configuration_file();

	/*
	 * Walk the lcollection, marking active collections so inactive ones
	 * can be freed.
	 */
	list_walk_collection(collection_clear_cb, NULL);
	lcollection_update(LCU_ACTIVE_ONLY); /* mark */
	list_walk_collection(collection_sweep_cb, NULL);
}

/*
 * Respond to SIGHUP by triggering the rereading the configuration file and cap
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
	(unsigned long long)(lcol->lcol_stat_invalidate ? 0 : \
	    (lcol->lcol_stat.field - lcol->lcol_stat_old.field))
#define	VALID(field) \
	(unsigned long long)(lcol->lcol_stat_invalidate ? 0 : \
	    lcol->lcol_stat.field)

	debug("%s %s status: succeeded/attempted (k): %llu/%llu, "
	    "ineffective/scans/unenforced/samplings:  %llu/%llu/%llu/%llu, RSS "
	    "min/max (k): %llu/%llu, cap %llu kB, processes/thpt: %llu/%llu, "
	    "%llu scans over %llu ms\n", rcfg.rcfg_mode_name, lcol->lcol_name,
	    DELTA(lcols_pg_eff), DELTA(lcols_pg_att),
	    DELTA(lcols_scan_ineffective), DELTA(lcols_scan),
	    DELTA(lcols_unenforced_cap), DELTA(lcols_rss_sample),
	    VALID(lcols_min_rss), VALID(lcols_max_rss),
	    (unsigned long long)lcol->lcol_rss_cap,
	    (unsigned long long)(lcol->lcol_stat.lcols_proc_in -
	    lcol->lcol_stat.lcols_proc_out), DELTA(lcols_proc_out),
	    DELTA(lcols_scan_count), DELTA(lcols_scan_time_complete) / (NANOSEC
	    / MILLISEC));

#undef DELTA
#undef VALID

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
		/*
		 * Set a flag to indicate that the exported interval snapshot
		 * values should be reset at the next sample.
		 */
		lcol->lcol_stat_invalidate = 1;
	} else {
		debug("can't write %s %s statistics", rcfg.rcfg_mode_name,
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
			} else
				return (-1);
		}
	}

	*scannedp = scanned;
	return (0);
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
	int old_enforce_caps;		/* track changes in enforcement */
					/* conditions */
	soft_scan_arg_t arg;

	(void) set_message_priority(RCM_INFO);
	(void) setprogname("rcapd");
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

	/*
	 * Read the configuration file.
	 */
	if (rcfg_read(RCAPD_DEFAULT_CONF_FILE, -1, &rcfg, verify_statistics)
	    != 0)
		die(gettext("invalid configuration: %s"),
		    RCAPD_DEFAULT_CONF_FILE);
	finish_configuration();
	should_reconfigure = 0;

	/*
	 * Check that required privileges are possessed.
	 */
	verify_and_set_privileges();

	now = next_report = next_proc_walk = next_rss_sample = gethrtime();
	next_configuration = NEXT_EVENT_TIME(gethrtime(),
	    rcfg.rcfg_reconfiguration_interval);

	if (rcfg.rcfg_memory_cap_enforcement_pressure == 0) {
		/*
		 * Always enforce caps when strict caps are used.
		 */
		enforce_caps = 1;
	}

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
	if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
		debug("fd limit: %lu\n", rl.rlim_cur);
	else
		debug("fd limit: unknown\n");

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
	 * enforcing their caps.  Look for changes in caps and process
	 * membership, as well as responding to requests to reread the
	 * configuration.  Update per-collection statistics periodically.
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
		 * Update the process list once every proc_walk_interval.  The
		 * condition of global memory pressure is also checked at the
		 * same frequency, if strict caps are in use.
		 */
		now = gethrtime();

		/*
		 * Detect configuration and cap changes at every
		 * reconfiguration_interval, or when SIGHUP has been received.
		 */
		if (EVENT_TIME(now, next_configuration) ||
		    should_reconfigure == 1) {
			reconfigure();
			next_configuration = NEXT_EVENT_TIME(now,
			    rcfg.rcfg_reconfiguration_interval);

			/*
			 * Reset each event time to the shorter of the
			 * previous and new intervals.
			 */
			if (next_report == 0 &&
			    rcfg.rcfg_report_interval > 0)
				next_report = now;
			else
				next_report = POSITIVE_MIN(next_report,
				    NEXT_REPORT_EVENT_TIME(now,
				    rcfg.rcfg_report_interval));
			if (next_proc_walk == 0 &&
			    rcfg.rcfg_proc_walk_interval > 0)
				next_proc_walk = now;
			else
				next_proc_walk = POSITIVE_MIN(next_proc_walk,
				    NEXT_EVENT_TIME(now,
				    rcfg.rcfg_proc_walk_interval));
			if (next_rss_sample == 0 &&
			    rcfg.rcfg_rss_sample_interval > 0)
				next_rss_sample = now;
			else
				next_rss_sample = POSITIVE_MIN(next_rss_sample,
				    NEXT_EVENT_TIME(now,
				    rcfg.rcfg_rss_sample_interval));

			should_reconfigure = 0;
			continue;
		}

		if (EVENT_TIME(now, next_proc_walk)) {
			debug("scanning process list...\n");
			proc_walk_all(proc_cb); /* mark */
			list_walk_all(sweep_process_cb);
			next_proc_walk = NEXT_EVENT_TIME(now,
			    rcfg.rcfg_proc_walk_interval);
		}

		if (EVENT_TIME(now, next_rss_sample)) {
			/*
			 * Check for changes to the amount of installed
			 * physical memory, to compute the current memory
			 * pressure.
			 */
			update_phys_total();

			/*
			 * If soft caps are in use, determine if global memory
			 * pressure exceeds the configured maximum above which
			 * soft caps are enforced.
			 */
			memory_pressure = 100 -
			    (int)((sysconf(_SC_AVPHYS_PAGES) *
			    (sysconf(_SC_PAGESIZE) / 1024)) * 100.0 /
			    phys_total);
			memory_pressure_sample++;
			if (rcfg.rcfg_memory_cap_enforcement_pressure > 0) {
				if (memory_pressure >
				    rcfg.rcfg_memory_cap_enforcement_pressure) {
					if (enforce_soft_caps == 0) {
						debug("memory pressure %d%%\n",
						    memory_pressure);
						enforce_soft_caps = 1;
					}
				} else {
					if (enforce_soft_caps == 1)
						enforce_soft_caps = 0;
				}
			}

			/*
			 * Determine if the global page scanner is running,
			 * while which no memory caps should be enforced, to
			 * prevent interference with the global page scanner.
			 */
			if (get_globally_scanned_pages(&new_sp) == 0) {
				if (old_sp == 0)
					/*EMPTY*/
					;
				else if ((new_sp - old_sp) > 0) {
					if (global_scanner_running == 0) {
						debug("global memory pressure "
						    "detected (%llu pages "
						    "scanned since last "
						    "interval)\n",
						    (unsigned long long)
						    (new_sp - old_sp));
						global_scanner_running = 1;
					}
				} else if (global_scanner_running == 1) {
					debug("global memory pressure "
					    "relieved\n");
					global_scanner_running = 0;
				}
				old_sp = new_sp;
			} else {
				warn(gettext("kstat_read() failed"));
				new_sp = old_sp;
			}

			/*
			 * Cap enforcement is determined by the previous two
			 * conditions.
			 */
			old_enforce_caps = enforce_caps;
			enforce_caps =
			    (rcfg.rcfg_memory_cap_enforcement_pressure ==
			    0 || enforce_soft_caps == 1) &&
			    !global_scanner_running;
			if (old_enforce_caps != enforce_caps)
				debug("%senforcing caps\n", enforce_caps == 0 ?
				    "not " : "");

			/*
			 * Sample collections' member processes' RSSes and
			 * recompute collections' excess.
			 */
			list_walk_all(mem_sample_cb);
			list_walk_collection(collection_zero_mem_cb, NULL);
			list_walk_all(memory_all_cb);
			list_walk_collection(rss_sample_col_cb, NULL);
			if (rcfg.rcfg_memory_cap_enforcement_pressure > 0)
				debug("memory pressure %d%%\n",
				    memory_pressure);
			list_walk_collection(excess_print_cb, NULL);

			/*
			 * If soft caps are in use, determine the size of the
			 * portion from each collection to scan for.
			 */
			if (enforce_soft_caps == 1) {
				/*
				 * Compute the sum of the collections'
				 * excesses, which will be the denominator.
				 */
				arg.ssa_sum_excess = 0;
				list_walk_collection(sum_excess_cb,
				    &arg.ssa_sum_excess);

				/*
				 * Compute the quantity of memory (in
				 * kilobytes) above the cap enforcement
				 * pressure.  Set the scan goal to that
				 * quantity (or at most the excess).
				 */
				arg.ssa_scan_goal = MIN((
				    sysconf(_SC_PHYS_PAGES) * (100 -
				    rcfg.rcfg_memory_cap_enforcement_pressure)
				    / 100 - sysconf(_SC_AVPHYS_PAGES)) *
				    (sysconf(_SC_PAGESIZE) / 1024),
				    arg.ssa_sum_excess);
			}

			/*
			 * Victimize offending collections.
			 */
			if (enforce_caps == 1 && ((enforce_soft_caps == 1 &&
			    arg.ssa_scan_goal > 0 && arg.ssa_sum_excess > 0) ||
			    (enforce_soft_caps == 0)))
				if (enforce_soft_caps == 1) {
					debug("scan goal is %lldKB\n",
					    (long long)arg.ssa_scan_goal);
					list_walk_collection(soft_scan_cb,
					    &arg);
				} else
					list_walk_collection(scan_cb, NULL);
			else
				list_walk_collection(unenforced_cap_cb, NULL);

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
		next = POSITIVE_MIN(next, next_proc_walk);
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
