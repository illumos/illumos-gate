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
 * Copyright 2014, Joyent, Inc.  All rights reserved.
 */

/*
 * This file implements the code which runs a thread inside zoneadmd to cap
 * the associated zone's physical memory.  A thread to do this is started
 * when the zone boots and is halted when the zone shuts down.
 *
 * Because of the way that the VM system is currently implemented, there is no
 * way to go from the bottom up (page to process to zone).  Thus, there is no
 * obvious way to hook an rctl into the kernel's paging code to enforce a hard
 * memory cap.  Instead, we implement a soft physical memory cap which looks
 * at the zone's overall rss and once it is over the cap, works from the top
 * down (zone to process to page), looking at zone processes, to determine
 * what to try to pageout to get the zone under its memory cap.
 *
 * The code uses the fast, cheap, but potentially very inaccurate sum of the
 * rss values from psinfo_t to first approximate the zone's rss and will
 * fallback to the vm_getusage syscall to determine the zone's rss if needed.
 * It then checks the rss against the zone's zone.max-physical-memory rctl.
 * Once the zone goes over its cap, then this thread will work through the
 * zone's /proc process list, Pgrab-bing each process and stepping through the
 * address space segments attempting to use pr_memcntl(...MS_INVALCURPROC...)
 * to pageout pages, until the zone is again under its cap.
 *
 * Although zone memory capping is implemented as a soft cap by this user-level
 * thread, the interfaces around memory caps that are exposed to the user are
 * the standard ones; an rctl and kstats.  This thread uses the rctl value
 * to obtain the cap and works with the zone kernel code to update the kstats.
 * If the implementation ever moves into the kernel, these exposed interfaces
 * do not need to change.
 *
 * The thread adaptively sleeps, periodically checking the state of the
 * zone.  As the zone's rss gets closer to the cap, the thread will wake up
 * more often to check the zone's status.  Once the zone is over the cap,
 * the thread will work to pageout until the zone is under the cap, as shown
 * by updated vm_usage data.
 *
 * NOTE: The pagedata page maps (at least on x86) are not useful.  Those flags
 * are set by hrm_setbits() and on x86 that code path is only executed by
 *     segvn_pagelock -> hat_setstat -> hrm_setbits
 *     segvn_softunlock -^
 * On SPARC there is an additional code path which may make this data
 * useful (sfmmu_ttesync), but since it is not generic, we ignore the page
 * maps.  If we ever fix this issue, then we could generalize this mcap code to
 * do more with the data on active pages.
 *
 * For debugging, touch the file {zonepath}/mcap_debug.log.  This will
 * cause the thread to start logging its actions into that file (it may take
 * a minute or two if the thread is currently sleeping).  Removing that
 * file will cause logging to stop.
 */

#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <procfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/priocntl.h>
#include <dirent.h>
#include <zone.h>
#include <libzonecfg.h>
#include <thread.h>
#include <values.h>
#include <sys/vm_usage.h>
#include <sys/resource.h>
#include <sys/debug.h>
#include <synch.h>
#include <wait.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include <sys/contract/process.h>
#include "zoneadmd.h"

					/* round up to next y = 2^n */
#define	ROUNDUP(x, y)	(((x) + ((y) - 1)) & ~((y) - 1))

#define	CAP_REFRESH	((uint64_t)300 * NANOSEC) /* every 5 minutes */

/*
 * zonecfg attribute tunables for memory capping.
 *    phys-mcap-cmd
 *	type: string
 *	specifies a command that can be run when over the cap
 *    phys-mcap-no-vmusage
 *	type: boolean
 *	true disables vm_getusage and just uses zone's proc. rss sum
 *    phys-mcap-no-pageout
 *	type: boolean
 *	true disables pageout when over
 *    phys-mcap-no-pf-throttle
 *	type: boolean
 *	true disables page fault throttling when over
 */
#define	TUNE_CMD	"phys-mcap-cmd"
#define	TUNE_NVMU	"phys-mcap-no-vmusage"
#define	TUNE_NPAGE	"phys-mcap-no-pageout"
#define	TUNE_NPFTHROT	"phys-mcap-no-pf-throttle"

/*
 * These are only used in get_mem_info but global. We always need scale_rss and
 * prev_fast_rss to be persistent but we also have the other two global so we
 * can easily see these with mdb.
 */
uint64_t	scale_rss = 0;
uint64_t	prev_fast_rss = 0;
uint64_t	fast_rss = 0;
uint64_t	accurate_rss = 0;

static char	zonename[ZONENAME_MAX];
static char	zonepath[MAXPATHLEN];
static char	zoneproc[MAXPATHLEN];
static char	debug_log[MAXPATHLEN];
static zoneid_t	zid;
static mutex_t	shutdown_mx;
static cond_t	shutdown_cv;
static int	shutting_down = 0;
static thread_t mcap_tid;
static FILE	*debug_log_fp = NULL;
static uint64_t zone_rss_cap;		/* RSS cap(KB) */
static char	over_cmd[2 * BUFSIZ];	/* same size as zone_attr_value */
static boolean_t skip_vmusage = B_FALSE;
static boolean_t skip_pageout = B_FALSE;
static boolean_t skip_pf_throttle = B_FALSE;

static zlog_t	*logp;

static int64_t check_suspend();
static void get_mcap_tunables();

/*
 * Structure to hold current state about a process address space that we're
 * working on.
 */
typedef struct {
	int pr_curr;		/* the # of the mapping we're working on */
	int pr_nmap;		/* number of mappings in address space */
	prmap_t *pr_mapp;	/* process's map array */
} proc_map_t;

typedef struct zsd_vmusage64 {
	id_t vmu_zoneid;
	uint_t vmu_type;
	id_t vmu_id;
	/*
	 * An amd64 kernel will align the following uint64_t members, but a
	 * 32bit i386 process will not without help.
	 */
	int vmu_align_next_members_on_8_bytes;
	uint64_t vmu_rss_all;
	uint64_t vmu_rss_private;
	uint64_t vmu_rss_shared;
	uint64_t vmu_swap_all;
	uint64_t vmu_swap_private;
	uint64_t vmu_swap_shared;
} zsd_vmusage64_t;

/*
 * Output a debug log message.
 */
/*PRINTFLIKE1*/
static void
debug(char *fmt, ...)
{
	va_list ap;

	if (debug_log_fp == NULL)
		return;

	va_start(ap, fmt);
	(void) vfprintf(debug_log_fp, fmt, ap);
	va_end(ap);
	(void) fflush(debug_log_fp);
}

/*
 * Like sleep(3C) but can be interupted by cond_signal which is posted when
 * we're shutting down the mcap thread.
 */
static void
sleep_shutdown(int secs)
{
	timestruc_t to;

	to.tv_sec = secs;
	to.tv_nsec = 0;

	(void) mutex_lock(&shutdown_mx);
	if (!shutting_down)
		(void) cond_reltimedwait(&shutdown_cv, &shutdown_mx, &to);
	(void) mutex_unlock(&shutdown_mx);
}

static boolean_t
proc_issystem(pid_t pid)
{
	char pc_clname[PC_CLNMSZ];

	if (priocntl(P_PID, pid, PC_GETXPARMS, NULL, PC_KY_CLNAME, pc_clname,
	    PC_KY_NULL) != -1)
		return (strcmp(pc_clname, "SYS") == 0);

	return (B_TRUE);
}

/*
 * Fork a child that enters the zone and runs the "phys-mcap-cmd" command.
 */
static void
run_over_cmd()
{
	int		ctfd;
	int		err;
	pid_t		childpid;
	siginfo_t	info;
	ctid_t		ct;

	/*
	 * Before we enter the zone, we need to create a new process contract
	 * for the child, as required by zone_enter().
	 */
	if ((ctfd = open64("/system/contract/process/template", O_RDWR)) == -1)
		return;
	if (ct_tmpl_set_critical(ctfd, 0) != 0 ||
	    ct_tmpl_set_informative(ctfd, 0) != 0 ||
	    ct_pr_tmpl_set_fatal(ctfd, CT_PR_EV_HWERR) != 0 ||
	    ct_pr_tmpl_set_param(ctfd, CT_PR_PGRPONLY) != 0 ||
	    ct_tmpl_activate(ctfd) != 0) {
		(void) close(ctfd);
		return;
	}

	childpid = fork();
	switch (childpid) {
	case -1:
		(void) ct_tmpl_clear(ctfd);
		(void) close(ctfd);
		break;
	case 0:	/* Child */
		(void) ct_tmpl_clear(ctfd);
		(void) close(ctfd);
		if (zone_enter(zid) == -1)
			_exit(errno);
		err = system(over_cmd);
		_exit(err);
		break;
	default:	/* Parent */
		if (contract_latest(&ct) == -1)
			ct = -1;
		(void) ct_tmpl_clear(ctfd);
		(void) close(ctfd);
		err = waitid(P_PID, childpid, &info, WEXITED);
		(void) contract_abandon_id(ct);
		if (err == -1 || info.si_status != 0)
			debug("over_cmd failed");
		break;
	}
}

/*
 * Get the next mapping.
 */
static prmap_t *
nextmapping(proc_map_t *pmp)
{
	if (pmp->pr_mapp == NULL || pmp->pr_curr >= pmp->pr_nmap)
		return (NULL);

	return (&pmp->pr_mapp[pmp->pr_curr++]);
}

/*
 * Initialize the proc_map_t to access the first mapping of an address space.
 */
static prmap_t *
init_map(proc_map_t *pmp, pid_t pid)
{
	int fd;
	int res;
	struct stat st;
	char pathbuf[MAXPATHLEN];

	bzero(pmp, sizeof (proc_map_t));
	pmp->pr_nmap = -1;

	(void) snprintf(pathbuf, sizeof (pathbuf), "%s/%d/map", zoneproc, pid);
	if ((fd = open(pathbuf, O_RDONLY, 0)) < 0)
		return (NULL);

redo:
	errno = 0;
	if (fstat(fd, &st) != 0)
		goto done;

	if ((pmp->pr_mapp = malloc(st.st_size)) == NULL) {
		debug("cannot malloc() %ld bytes for xmap", st.st_size);
		goto done;
	}
	(void) bzero(pmp->pr_mapp, st.st_size);

	errno = 0;
	if ((res = pread(fd, pmp->pr_mapp, st.st_size, 0)) != st.st_size) {
		free(pmp->pr_mapp);
		pmp->pr_mapp = NULL;
		if (res > 0 || errno == E2BIG) {
			goto redo;
		} else {
			debug("pid %ld cannot read xmap\n", pid);
			goto done;
		}
	}

	pmp->pr_nmap = st.st_size / sizeof (prmap_t);

done:
	(void) close(fd);
	return (nextmapping(pmp));
}

/*
 * Attempt to invalidate the entire mapping from within the given process's
 * address space. May return nonzero with errno as:
 *    ESRCH  - process not found
 *    ENOMEM - segment not found
 *    EINVAL - mapping exceeds a single segment
 */
static int
pageout_mapping(pid_t pid, prmap_t *pmp)
{
	int res;

	if (pmp->pr_mflags & MA_ISM || pmp->pr_mflags & MA_SHM)
		return (0);

	errno = 0;
	res = syscall(SYS_rusagesys, _RUSAGESYS_INVALMAP, pid, pmp->pr_vaddr,
	    pmp->pr_size);

	return (res);
}

/*
 * Work through a process paging out mappings until the whole address space was
 * examined or the excess is < 0.  Return our estimate of the updated excess.
 */
static int64_t
pageout_process(pid_t pid, int64_t excess)
{
	int			psfd;
	prmap_t			*pmap;
	proc_map_t		cur;
	int			res;
	int64_t			sum_d_rss, d_rss;
	int64_t			old_rss;
	int			map_cnt;
	psinfo_t		psinfo;
	char			pathbuf[MAXPATHLEN];

	(void) snprintf(pathbuf, sizeof (pathbuf), "%s/%d/psinfo", zoneproc,
	    pid);
	if ((psfd = open(pathbuf, O_RDONLY, 0000)) < 0)
		return (excess);

	cur.pr_mapp = NULL;

	if (pread(psfd, &psinfo, sizeof (psinfo), 0) != sizeof (psinfo))
		goto done;

	old_rss = (int64_t)psinfo.pr_rssize;
	map_cnt = 0;

	/* If unscannable, skip it. */
	if (psinfo.pr_nlwp == 0 || proc_issystem(pid)) {
		debug("pid %ld: system process, skipping %s\n",
		    pid, psinfo.pr_psargs);
		goto done;
	}

	/* If tiny RSS (16KB), skip it. */
	if (old_rss <= 16) {
		debug("pid %ld: skipping, RSS %lldKB %s\n",
		    pid, old_rss, psinfo.pr_psargs);
		goto done;
	}

	/* Get segment residency information. */
	pmap = init_map(&cur, pid);

	/* Skip process if it has no mappings. */
	if (pmap == NULL) {
		debug("pid %ld: map unreadable; ignoring\n", pid);
		goto done;
	}

	debug("pid %ld: nmap %d sz %dKB rss %lldKB %s\n",
	    pid, cur.pr_nmap, psinfo.pr_size, old_rss, psinfo.pr_psargs);

	/*
	 * Within the process's address space, attempt to page out mappings.
	 */
	sum_d_rss = 0;
	while (excess > 0 && pmap != NULL && !shutting_down) {
		/* invalidate the entire mapping */
		if ((res = pageout_mapping(pid, pmap)) < 0)
			debug("pid %ld: mapping 0x%p %ldkb unpageable (%d)\n",
			    pid, pmap->pr_vaddr, pmap->pr_size / 1024, errno);

		map_cnt++;

		/*
		 * Re-check the process rss and get the delta.
		 */
		if (pread(psfd, &psinfo, sizeof (psinfo), 0)
		    != sizeof (psinfo)) {
			excess -= old_rss;
			goto done;
		}

		d_rss = (int64_t)psinfo.pr_rssize - old_rss;
		old_rss = (int64_t)psinfo.pr_rssize;
		sum_d_rss += d_rss;

		/*
		 * d_rss hopefully should be negative (or 0 if nothing
		 * invalidated) but can be positive if more got paged in.
		 */
		excess += d_rss;

		if (excess <= 0) {
			debug("pid %ld: (part.) nmap %d delta_rss %lldKB "
			    "excess %lldKB\n", pid, map_cnt,
			    (unsigned long long)sum_d_rss, (long long)excess);
			map_cnt = 0;

			/*
			 * If we're actually under, this will suspend checking
			 * in the middle of this process's address space.
			 */
			excess = check_suspend();
			if (shutting_down)
				goto done;

			/*
			 * since we might have suspended, re-read process's rss
			 */
			if (pread(psfd, &psinfo, sizeof (psinfo), 0)
			    != sizeof (psinfo)) {
				excess -= old_rss;
				goto done;
			}

			old_rss = (int64_t)psinfo.pr_rssize;

			debug("pid %ld: resume pageout; excess %lld\n", pid,
			    (long long)excess);
			sum_d_rss = 0;
		}

		pmap = nextmapping(&cur);
	}

	debug("pid %ld: nmap %d delta_rss %lldKB excess %lldKB\n",
	    pid, map_cnt, (unsigned long long)sum_d_rss, (long long)excess);

done:
	if (cur.pr_mapp != NULL)
		free(cur.pr_mapp);

	(void) close(psfd);

	if (shutting_down)
		return (0);

	return (excess);
}

/*
 * Get the zone's RSS data.
 */
static uint64_t
get_mem_info()
{
	uint64_t		n = 1;
	zsd_vmusage64_t		buf;
	uint64_t		tmp_rss;
	DIR			*pdir = NULL;
	struct dirent		*dent;

	/*
	 * Start by doing the fast, cheap RSS calculation using the rss value
	 * in psinfo_t.  Because that's per-process, it can lead to double
	 * counting some memory and overestimating how much is being used, but
	 * as long as that's not over the cap, then we don't need do the
	 * expensive calculation.
	 *
	 * If we have to do the expensive calculation, we remember the scaling
	 * factor so that we can try to use that on subsequent iterations for
	 * the fast rss.
	 */
	if (shutting_down)
		return (0);

	if ((pdir = opendir(zoneproc)) == NULL)
		return (0);

	accurate_rss = 0;
	fast_rss = 0;
	while (!shutting_down && (dent = readdir(pdir)) != NULL) {
		pid_t		pid;
		int		psfd;
		int64_t		rss;
		char		pathbuf[MAXPATHLEN];
		psinfo_t	psinfo;

		if (strcmp(".", dent->d_name) == 0 ||
		    strcmp("..", dent->d_name) == 0)
			continue;

		pid = atoi(dent->d_name);
		if (pid == 0 || pid == 1)
			continue;

		(void) snprintf(pathbuf, sizeof (pathbuf), "%s/%d/psinfo",
		    zoneproc, pid);

		rss = 0;
		if ((psfd = open(pathbuf, O_RDONLY, 0000)) != -1) {
			if (pread(psfd, &psinfo, sizeof (psinfo), 0) ==
			    sizeof (psinfo))
				rss = (int64_t)psinfo.pr_rssize;

			(void) close(psfd);
		}

		fast_rss += rss;
	}

	(void) closedir(pdir);

	if (shutting_down)
		return (0);

	debug("fast rss: %lluKB, scale: %llu, prev: %lluKB\n", fast_rss,
	    scale_rss, prev_fast_rss);

	/* see if we can get by with a scaled fast rss */
	tmp_rss = fast_rss;
	if (scale_rss > 1 && prev_fast_rss > 0) {
		/*
		 * Only scale the fast value if it hasn't ballooned too much
		 * to trust.
		 */
		if (fast_rss / prev_fast_rss < 2) {
			fast_rss /= scale_rss;
			debug("scaled fast rss: %lluKB\n", fast_rss);
		}
	}

	if (fast_rss <= zone_rss_cap || skip_vmusage) {
		uint64_t zone_rss_bytes;

		zone_rss_bytes = fast_rss * 1024;
		/* Use the zone's approx. RSS in the kernel */
		(void) zone_setattr(zid, ZONE_ATTR_RSS, &zone_rss_bytes, 0);
		return (fast_rss);
	}

	buf.vmu_id = zid;

	/* get accurate usage (cached data may be up to 5 seconds old) */
	if (syscall(SYS_rusagesys, _RUSAGESYS_GETVMUSAGE, VMUSAGE_A_ZONE, 5,
	    (uintptr_t)&buf, (uintptr_t)&n) != 0) {
		debug("vmusage failed\n");
		(void) sleep_shutdown(1);
		return (0);
	}

	if (n > 1) {
		/* This should never happen */
		debug("vmusage returned more than one result\n");
		(void) sleep_shutdown(1);
		return (0);
	}

	if (buf.vmu_id != zid) {
		/* This should never happen */
		debug("vmusage returned the incorrect zone\n");
		(void) sleep_shutdown(1);
		return (0);
	}

	accurate_rss = buf.vmu_rss_all / 1024;

	/* calculate scaling factor to use for fast_rss from now on */
	if (accurate_rss > 0) {
		scale_rss = fast_rss / accurate_rss;
		debug("new scaling factor: %llu\n", scale_rss);
		/* remember the fast rss when we had to get the accurate rss */
		prev_fast_rss = tmp_rss;
	}

	debug("accurate rss: %lluKB, scale: %llu, prev: %lluKB\n", accurate_rss,
	    scale_rss, prev_fast_rss);
	return (accurate_rss);
}

/*
 * Needed to read the zones physical-memory-cap rctl.
 */
static struct ps_prochandle *
grab_zone_proc()
{
	DIR *dirp;
	struct dirent *dentp;
	struct ps_prochandle *ph = NULL;
	int tmp;

	if ((dirp = opendir(zoneproc)) == NULL)
		return (NULL);

	while (!shutting_down && (dentp = readdir(dirp))) {
		int pid;

		if (strcmp(".", dentp->d_name) == 0 ||
		    strcmp("..", dentp->d_name) == 0)
			continue;

		pid = atoi(dentp->d_name);
		/* attempt to grab process */
		if ((ph = Pgrab(pid, 0, &tmp)) != NULL) {
			if (Psetflags(ph, PR_RLC) == 0) {
				if (Pcreate_agent(ph) == 0) {
					(void) closedir(dirp);
					return (ph);
				}
			}
			Prelease(ph, 0);
		}
	}

	(void) closedir(dirp);
	return (NULL);
}

static uint64_t
get_zone_cap()
{
	rctlblk_t *rblk;
	uint64_t mcap;
	struct ps_prochandle *ph;

	if ((rblk = (rctlblk_t *)malloc(rctlblk_size())) == NULL)
		return (UINT64_MAX);

	if ((ph = grab_zone_proc()) == NULL) {
		free(rblk);
		return (UINT64_MAX);
	}

	if (pr_getrctl(ph, "zone.max-physical-memory", NULL, rblk,
	    RCTL_FIRST)) {
		Pdestroy_agent(ph);
		Prelease(ph, 0);
		free(rblk);
		return (UINT64_MAX);
	}

	Pdestroy_agent(ph);
	Prelease(ph, 0);

	mcap = rctlblk_get_value(rblk);
	free(rblk);
	return (mcap);
}

/*
 * check_suspend is invoked at the beginning of every pass through the process
 * list or after we've paged out enough so that we think the excess is under
 * the cap.  The purpose is to periodically check the zone's rss and return
 * the excess when the zone is over the cap.  The rest of the time this
 * function will sleep, periodically waking up to check the current rss.
 *
 * Depending on the percentage of penetration of the zone's rss into the
 * cap we sleep for longer or shorter amounts. This reduces the impact of this
 * work on the system, which is important considering that each zone will be
 * monitoring its rss.
 */
static int64_t
check_suspend()
{
	static hrtime_t last_cap_read = 0;
	static uint64_t addon;
	static uint64_t lo_thresh;	/* Thresholds for how long to  sleep */
	static uint64_t hi_thresh;	/* when under the cap (80% & 90%). */
	static uint64_t prev_zone_rss = 0;
	static uint32_t pfdelay = 0;	/* usec page fault delay when over */

	/* Wait a second to give the async pageout a chance to catch up. */
	(void) sleep_shutdown(1);

	while (!shutting_down) {
		int64_t new_excess;
		int sleep_time;
		hrtime_t now;
		struct stat st;
		uint64_t zone_rss;		/* total RSS(KB) */

		/*
		 * Check if the debug log files exists and enable or disable
		 * debug.
		 */
		if (debug_log_fp == NULL) {
			if (stat(debug_log, &st) == 0)
				debug_log_fp = fopen(debug_log, "w");
		} else {
			if (stat(debug_log, &st) == -1) {
				(void) fclose(debug_log_fp);
				debug_log_fp = NULL;
			}
		}

		/*
		 * If the CAP_REFRESH interval has passed, re-get the current
		 * cap in case it has been dynamically updated.
		 */
		now = gethrtime();
		if (now - last_cap_read > CAP_REFRESH) {
			uint64_t mcap;

			last_cap_read = now;

			mcap = get_zone_cap();
			if (mcap != 0 && mcap != UINT64_MAX)
				zone_rss_cap = ROUNDUP(mcap, 1024) / 1024;
			else
				zone_rss_cap = UINT64_MAX;

			lo_thresh = (uint64_t)(zone_rss_cap * .8);
			hi_thresh = (uint64_t)(zone_rss_cap * .9);
			addon = (uint64_t)(zone_rss_cap * 0.05);

			/*
			 * We allow the memory cap tunables to be changed on
			 * the fly.
			 */
			get_mcap_tunables();

			debug("%s: %s\n", TUNE_CMD, over_cmd);
			debug("%s: %d\n", TUNE_NVMU, skip_vmusage);
			debug("%s: %d\n", TUNE_NPAGE, skip_pageout);
			debug("%s: %d\n", TUNE_NPFTHROT, skip_pf_throttle);
			debug("current cap %lluKB lo %lluKB hi %lluKB\n",
			    zone_rss_cap, lo_thresh, hi_thresh);
		}

		/* No cap, nothing to do. */
		if (zone_rss_cap == 0 || zone_rss_cap == UINT64_MAX) {
			debug("no cap, sleep 120 seconds\n");
			(void) sleep_shutdown(120);
			continue;
		}

		zone_rss = get_mem_info();

		/* calculate excess */
		new_excess = zone_rss - zone_rss_cap;

		debug("rss %lluKB, cap %lluKB, excess %lldKB\n",
		    zone_rss, zone_rss_cap, new_excess);

		/*
		 * If necessary, updates stats.
		 */

		/*
		 * If it looks like we did some paging out since last over the
		 * cap then update the kstat so we can approximate how much was
		 * paged out.
		 */
		if (prev_zone_rss > zone_rss_cap && zone_rss < prev_zone_rss) {
			uint64_t diff;

			/* assume diff is num bytes we paged out */
			diff = (prev_zone_rss - zone_rss) * 1024;

			(void) zone_setattr(zid, ZONE_ATTR_PMCAP_PAGEOUT,
			    &diff, 0);
		}
		prev_zone_rss = zone_rss;

		if (new_excess > 0) {
			uint64_t n = 1;

			/* Increment "nover" kstat. */
			(void) zone_setattr(zid, ZONE_ATTR_PMCAP_NOVER, &n, 0);

			if (!skip_pf_throttle) {
				/*
				 * Tell the kernel to start throttling page
				 * faults by some number of usecs to help us
				 * catch up. If we are persistently over the
				 * cap the delay ramps up to a max of 2000usecs.
				 * Note that for delays less than 1 tick
				 * (i.e. all of these) we busy-wait in as_fault.
				 *	delay	faults/sec
				 *	 125	8000
				 *	 250	4000
				 *	 500	2000
				 *	1000	1000
				 *	2000	 500
				 */
				if (pfdelay == 0)
					pfdelay = 125;
				else if (pfdelay < 2000)
					pfdelay *= 2;

				(void) zone_setattr(zid, ZONE_ATTR_PG_FLT_DELAY,
				    &pfdelay, 0);
			}

			/*
			 * Once we go over the cap, then we want to
			 * page out a little extra instead of stopping
			 * right at the cap. To do this we add 5% to
			 * the excess so that pageout_proces will work
			 * a little longer before stopping.
			 */
			return ((int64_t)(new_excess + addon));
		}

		/*
		 * At this point we are under the cap.
		 *
		 * Tell the kernel to stop throttling page faults.
		 *
		 * Scale the amount of time we sleep before rechecking the
		 * zone's memory usage.  Also, scale the accpetable age of
		 * cached results from vm_getusage.  We do this based on the
		 * penetration into the capped limit.
		 */
		if (pfdelay > 0) {
			pfdelay = 0;
			(void) zone_setattr(zid, ZONE_ATTR_PG_FLT_DELAY,
			    &pfdelay, 0);
		}

		if (zone_rss <= lo_thresh) {
			sleep_time = 120;
		} else if (zone_rss <= hi_thresh) {
			sleep_time = 60;
		} else {
			sleep_time = 30;
		}

		debug("sleep %d seconds\n", sleep_time);
		(void) sleep_shutdown(sleep_time);
	}

	/* Shutting down, tell the kernel so it doesn't throttle */
	if (pfdelay > 0) {
		pfdelay = 0;
		(void) zone_setattr(zid, ZONE_ATTR_PG_FLT_DELAY, &pfdelay, 0);
	}

	return (0);
}

static void
get_mcap_tunables()
{
	zone_dochandle_t handle;
	struct zone_attrtab attr;

	over_cmd[0] = '\0';
	if ((handle = zonecfg_init_handle()) == NULL)
		return;

	if (zonecfg_get_handle(zonename, handle) != Z_OK)
		goto done;

	/* Reset to defaults in case rebooting and settings have changed */
	over_cmd[0] = '\0';
	skip_vmusage = B_FALSE;
	skip_pageout = B_FALSE;
	skip_pf_throttle = B_FALSE;

	if (zonecfg_setattrent(handle) != Z_OK)
		goto done;
	while (zonecfg_getattrent(handle, &attr) == Z_OK) {
		if (strcmp(TUNE_CMD, attr.zone_attr_name) == 0) {
			(void) strlcpy(over_cmd, attr.zone_attr_value,
			    sizeof (over_cmd));
		} else if (strcmp(TUNE_NVMU, attr.zone_attr_name) == 0) {
			if (strcmp("true", attr.zone_attr_value) == 0)
				skip_vmusage = B_TRUE;
		} else if (strcmp(TUNE_NPAGE, attr.zone_attr_name) == 0) {
			if (strcmp("true", attr.zone_attr_value) == 0)
				skip_pageout = B_TRUE;
		} else if (strcmp(TUNE_NPFTHROT, attr.zone_attr_name) == 0) {
			if (strcmp("true", attr.zone_attr_value) == 0)
				skip_pf_throttle = B_TRUE;
		}
	}
	(void) zonecfg_endattrent(handle);

done:
	zonecfg_fini_handle(handle);
}

/* ARGSUSED */
static int
chk_proc_fs(void *data, const char *spec, const char *dir,
    const char *fstype, const char *opt)
{
	if (fstype != NULL && strcmp(fstype, "proc") == 0)
		*((boolean_t *)data) = B_TRUE;

	return (0);
}

static boolean_t
has_proc()
{
	brand_handle_t bh;
	boolean_t fnd = B_FALSE;

	if ((bh = brand_open(brand_name)) != NULL) {
		(void) brand_platform_iter_mounts(bh, chk_proc_fs, &fnd);
	}

	brand_close(bh);
	return (fnd);
}

/*
 * We run this loop for brands with no /proc to simply update the RSS, using
 * the cheap GZ /proc data, every 5 minutes.
 */
static void
no_procfs()
{
	DIR			*pdir = NULL;
	struct dirent		*dent;
	uint64_t		zone_rss_bytes;

	(void) sleep_shutdown(30);
	while (!shutting_down) {
		/*
		 * Just do the fast, cheap RSS calculation using the rss value
		 * in psinfo_t.  Because that's per-process, it can lead to
		 * double counting some memory and overestimating how much is
		 * being used. Since there is no /proc in the zone, we use the
		 * GZ /proc and check for the correct zone.
		 */
		if ((pdir = opendir("/proc")) == NULL)
			return;

		fast_rss = 0;
		while (!shutting_down && (dent = readdir(pdir)) != NULL) {
			pid_t		pid;
			int		psfd;
			int64_t		rss;
			char		pathbuf[MAXPATHLEN];
			psinfo_t	psinfo;

			if (strcmp(".", dent->d_name) == 0 ||
			    strcmp("..", dent->d_name) == 0)
				continue;

			pid = atoi(dent->d_name);
			if (pid == 0 || pid == 1)
				continue;

			(void) snprintf(pathbuf, sizeof (pathbuf),
			    "/proc/%d/psinfo", pid);

			rss = 0;
			if ((psfd = open(pathbuf, O_RDONLY, 0000)) != -1) {
				if (pread(psfd, &psinfo, sizeof (psinfo), 0) ==
				    sizeof (psinfo)) {
					if (psinfo.pr_zoneid == zid)
						rss = (int64_t)psinfo.pr_rssize;
				}

				(void) close(psfd);
			}

			fast_rss += rss;
		}

		(void) closedir(pdir);

		if (shutting_down)
			return;

		zone_rss_bytes = fast_rss * 1024;
		/* Use the zone's approx. RSS in the kernel */
		(void) zone_setattr(zid, ZONE_ATTR_RSS, &zone_rss_bytes, 0);

		(void) sleep_shutdown(300);
	}
}

/*
 * Thread that checks zone's memory usage and when over the cap, goes through
 * the zone's process list trying to pageout processes to get under the cap.
 */
static void
mcap_zone()
{
	DIR *pdir = NULL;
	int64_t excess;

	debug("thread startup\n");

	get_mcap_tunables();

	/*
	 * If the zone has no /proc filesystem, we can't use the fast algorithm
	 * to check RSS or pageout any processes. All we can do is periodically
	 * update it's RSS kstat using the expensive sycall.
	 */
	if (!has_proc()) {
		no_procfs();
		debug("thread shutdown\n");
		return;
	}

	/*
	 * When first starting it is likely lots of other zones are starting
	 * too because the system is booting.  Since we just started the zone
	 * we're not worried about being over the cap right away, so we let
	 * things settle a bit and tolerate some older data here to minimize
	 * the load on the system.
	 */
	(void) sleep_shutdown(15); /* wait 15 secs. so the zone can get going */

	/* Wait until zone's /proc is mounted */
	while (!shutting_down) {
		struct stat st;

		if (stat(zoneproc, &st) == 0 &&
		    strcmp(st.st_fstype, "proc") == 0)
			break;
		sleep_shutdown(5);
	}

	/* Open zone's /proc and walk entries. */
	while (!shutting_down) {
		if ((pdir = opendir(zoneproc)) != NULL)
			break;
		sleep_shutdown(5);
	}

	while (!shutting_down) {
		struct dirent *dirent;

		/* Wait until we've gone over the cap. */
		excess = check_suspend();

		debug("starting to scan, excess %lldk\n", (long long)excess);

		if (over_cmd[0] != '\0') {
			uint64_t zone_rss;	/* total RSS(KB) */

			debug("run phys_mcap_cmd: %s\n", over_cmd);
			run_over_cmd();

			zone_rss = get_mem_info();
			excess = zone_rss - zone_rss_cap;
			debug("rss %lluKB, cap %lluKB, excess %lldKB\n",
			    zone_rss, zone_rss_cap, excess);
			if (excess <= 0)
				continue;
		}

		while (!shutting_down && (dirent = readdir(pdir)) != NULL) {
			pid_t pid;

			if (strcmp(".", dirent->d_name) == 0 ||
			    strcmp("..", dirent->d_name) == 0)
				continue;

			pid = atoi(dirent->d_name);
			if (pid == 0 || pid == 1)
				continue;

			if (skip_pageout)
				(void) sleep_shutdown(2);
			else
				excess = pageout_process(pid, excess);

			if (excess <= 0) {
				debug("apparently under; excess %lld\n",
				    (long long)excess);
				/* Double check the current excess */
				excess = check_suspend();
			}
		}

		debug("process pass done; excess %lld\n", (long long)excess);
		rewinddir(pdir);

		if (skip_pageout)
			(void) sleep_shutdown(120);
	}

	if (pdir != NULL)
		(void) closedir(pdir);
	debug("thread shutdown\n");
}

void
create_mcap_thread(zlog_t *zlogp, zoneid_t id)
{
	int		res;
	char		brandname[MAXNAMELEN];

	shutting_down = 0;
	zid = id;
	logp = zlogp;
	(void) getzonenamebyid(zid, zonename, sizeof (zonename));

	if (zone_get_zonepath(zonename, zonepath, sizeof (zonepath)) != 0)
		zerror(zlogp, B_FALSE, "zone %s missing zonepath", zonename);

	brandname[0] = '\0';
	if (zone_get_brand(zonename, brandname, sizeof (brandname)) != 0)
		zerror(zlogp, B_FALSE, "zone %s missing brand", zonename);

	/* all but the lx brand currently use /proc */
	if (strcmp(brandname, "lx") == 0) {
		(void) snprintf(zoneproc, sizeof (zoneproc),
		    "%s/root/native/proc", zonepath);
	} else {
		(void) snprintf(zoneproc, sizeof (zoneproc), "%s/root/proc",
		    zonepath);
	}

	(void) snprintf(debug_log, sizeof (debug_log), "%s/mcap_debug.log",
	    zonepath);

	res = thr_create(NULL, NULL, (void *(*)(void *))mcap_zone, NULL, NULL,
	    &mcap_tid);
	if (res != 0) {
		zerror(zlogp, B_FALSE, "error %d creating memory cap thread",
		    res);
		mcap_tid = 0;
	}
}

void
destroy_mcap_thread()
{
	if (mcap_tid != 0) {
		shutting_down = 1;
		(void) cond_signal(&shutdown_cv);
		(void) thr_join(mcap_tid, NULL, NULL);
		mcap_tid = 0;
	}
}
