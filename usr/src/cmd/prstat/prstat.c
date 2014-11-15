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
 * Copyright (c) 2013 Gary Mills
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Portions Copyright 2009 Chad Mynhier
 */

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/loadavg.h>
#include <sys/time.h>
#include <sys/pset.h>
#include <sys/vm_usage.h>
#include <zone.h>
#include <libzonecfg.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#include <project.h>

#include <langinfo.h>
#include <libintl.h>
#include <locale.h>

#include "prstat.h"
#include "prutil.h"
#include "prtable.h"
#include "prsort.h"
#include "prfile.h"

/*
 * x86 <sys/regs.h> ERR conflicts with <curses.h> ERR.  For the purposes
 * of this file, we care about the curses.h ERR so include that last.
 */

#if	defined(ERR)
#undef	ERR
#endif

#ifndef	TEXT_DOMAIN			/* should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* use this only if it wasn't */
#endif

#include <curses.h>
#include <term.h>

#define	LOGIN_WIDTH	8
#define	ZONE_WIDTH	28
#define	PROJECT_WIDTH	28

#define	PSINFO_HEADER_PROC \
"   PID USERNAME  SIZE   RSS STATE  PRI NICE      TIME  CPU PROCESS/NLWP       "
#define	PSINFO_HEADER_PROC_LGRP \
"   PID USERNAME  SIZE   RSS STATE  PRI NICE      TIME  CPU LGRP PROCESS/NLWP  "
#define	PSINFO_HEADER_LWP \
"   PID USERNAME  SIZE   RSS STATE  PRI NICE      TIME  CPU PROCESS/LWPID      "
#define	PSINFO_HEADER_LWP_LGRP \
"   PID USERNAME  SIZE   RSS STATE  PRI NICE      TIME  CPU LGRP PROCESS/LWPID "
#define	USAGE_HEADER_PROC \
"   PID USERNAME USR SYS TRP TFL DFL LCK SLP LAT VCX ICX SCL SIG PROCESS/NLWP  "
#define	USAGE_HEADER_LWP \
"   PID USERNAME USR SYS TRP TFL DFL LCK SLP LAT VCX ICX SCL SIG PROCESS/LWPID "
#define	USER_HEADER_PROC \
" NPROC USERNAME  SWAP   RSS MEMORY      TIME  CPU                             "
#define	USER_HEADER_LWP \
"  NLWP USERNAME  SWAP   RSS MEMORY      TIME  CPU                             "
#define	TASK_HEADER_PROC \
"TASKID    NPROC  SWAP   RSS MEMORY      TIME  CPU PROJECT                     "
#define	TASK_HEADER_LWP \
"TASKID     NLWP  SWAP   RSS MEMORY      TIME  CPU PROJECT                     "
#define	PROJECT_HEADER_PROC \
"PROJID    NPROC  SWAP   RSS MEMORY      TIME  CPU PROJECT                     "
#define	PROJECT_HEADER_LWP \
"PROJID     NLWP  SWAP   RSS MEMORY      TIME  CPU PROJECT                     "
#define	ZONE_HEADER_PROC \
"ZONEID    NPROC  SWAP   RSS MEMORY      TIME  CPU ZONE                        "
#define	ZONE_HEADER_LWP \
"ZONEID     NLWP  SWAP   RSS MEMORY      TIME  CPU ZONE                        "
#define	PSINFO_LINE \
"%6d %-8s %5s %5s %-6s %3s  %3s %9s %3.3s%% %-.16s/%d"
#define	PSINFO_LINE_LGRP \
"%6d %-8s %5s %5s %-6s %3s  %3s %9s %3.3s%% %4d %-.16s/%d"
#define	USAGE_LINE \
"%6d %-8s %3.3s %3.3s %3.3s %3.3s %3.3s %3.3s %3.3s %3.3s %3.3s %3.3s "\
"%3.3s %3.3s %-.12s/%d"
#define	USER_LINE \
"%6d %-8s %5.5s %5.5s   %3.3s%% %9s %3.3s%%"
#define	TASK_LINE \
"%6d %8d %5s %5s   %3.3s%% %9s %3.3s%% %28s"
#define	PROJECT_LINE \
"%6d %8d %5s %5s   %3.3s%% %9s %3.3s%% %28s"
#define	ZONE_LINE \
"%6d %8d %5s %5s   %3.3s%% %9s %3.3s%% %28s"

#define	TOTAL_LINE \
"Total: %d processes, %d lwps, load averages: %3.2f, %3.2f, %3.2f"

/* global variables */

static char	*t_ulon;			/* termcap: start underline */
static char	*t_uloff;			/* termcap: end underline */
static char	*t_up;				/* termcap: cursor 1 line up */
static char	*t_eol;				/* termcap: clear end of line */
static char	*t_smcup;			/* termcap: cursor mvcap on */
static char	*t_rmcup;			/* termcap: cursor mvcap off */
static char	*t_home;			/* termcap: move cursor home */
static char	*movecur = NULL;		/* termcap: move up string */
static char	*empty_string = "\0";		/* termcap: empty string */
static uint_t	print_movecur = FALSE;		/* print movecur or not */
static int	is_curses_on = FALSE;		/* current curses state */

static table_t	pid_tbl = {0, 0, NULL};		/* selected processes */
static table_t	cpu_tbl = {0, 0, NULL};		/* selected processors */
static table_t  set_tbl = {0, 0, NULL};		/* selected processor sets */
static table_t	prj_tbl = {0, 0, NULL};		/* selected projects */
static table_t	tsk_tbl = {0, 0, NULL};		/* selected tasks */
static table_t	lgr_tbl = {0, 0, NULL};		/* selected lgroups */
static zonetbl_t zone_tbl = {0, 0, NULL};	/* selected zones */
static uidtbl_t euid_tbl = {0, 0, NULL}; 	/* selected effective users */
static uidtbl_t ruid_tbl = {0, 0, NULL}; 	/* selected real users */

static uint_t	total_procs;			/* total number of procs */
static uint_t	total_lwps;			/* total number of lwps */
static float	total_cpu;			/* total cpu usage */
static float	total_mem;			/* total memory usage */

static list_t	lwps;				/* list of lwps/processes */
static list_t	users;				/* list of users */
static list_t	tasks;				/* list of tasks */
static list_t	projects;			/* list of projects */
static list_t	zones;				/* list of zones */
static list_t	lgroups;			/* list of lgroups */

static volatile uint_t sigwinch = 0;
static volatile uint_t sigtstp = 0;
static volatile uint_t sigterm = 0;

static long pagesize;

/* default settings */

static optdesc_t opts = {
	5,			/* interval between updates, seconds */
	15,			/* number of lines in top part */
	5,			/* number of lines in bottom part */
	-1,			/* number of iterations; infinitely */
	OPT_PSINFO | OPT_FULLSCREEN | OPT_USEHOME | OPT_TERMCAP,
	-1			/* sort in decreasing order */
};

/*
 * Print timestamp as decimal reprentation of time_t value (-d u was specified)
 * or the standard date format (-d d was specified).
 */
static void
print_timestamp(void)
{
	time_t t = time(NULL);
	static char *fmt = NULL;

	/* We only need to retrieve this once per invocation */
	if (fmt == NULL)
		fmt = nl_langinfo(_DATE_FMT);

	if (opts.o_outpmode & OPT_UDATE) {
		(void) printf("%ld", t);
	} else if (opts.o_outpmode & OPT_DDATE) {
		char dstr[64];
		int len;

		len = strftime(dstr, sizeof (dstr), fmt, localtime(&t));
		if (len > 0)
			(void) printf("%s", dstr);
	}
	(void) putp(t_eol);
	(void) putchar('\n');
}

static void
psetloadavg(long psetid, void *ptr)
{
	double psetloadavg[3];
	double *loadavg = ptr;

	if (pset_getloadavg((psetid_t)psetid, psetloadavg, 3) != -1) {
		*loadavg++ += psetloadavg[0];
		*loadavg++ += psetloadavg[1];
		*loadavg += psetloadavg[2];
	}
}

/*
 * Queries the memory virtual and rss size for each member of a list.
 * This will override the values computed by /proc aggregation.
 */
static void
list_getsize(list_t *list)
{
	id_info_t *id;
	vmusage_t *results, *next;
	vmusage_t *match;
	size_t nres = 0;
	size_t i;
	uint_t flags = 0;
	int ret;
	size_t physmem = sysconf(_SC_PHYS_PAGES) * pagesize;

	/*
	 * Determine what swap/rss results to calculate.  getvmusage() will
	 * prune results returned to non-global zones automatically, so
	 * there is no need to pass different flags when calling from a
	 * non-global zone.
	 *
	 * Currently list_getsize() is only called with a single flag.  This
	 * is because -Z, -J, -T, and -a are mutually exclusive.  Regardless
	 * of this, we handle multiple flags.
	 */
	if (opts.o_outpmode & OPT_USERS) {
		/*
		 * Gather rss for all users in all zones.  Treat the same
		 * uid in different zones as the same user.
		 */
		flags |= VMUSAGE_COL_RUSERS;

	} else if (opts.o_outpmode & OPT_TASKS) {
		/* Gather rss for all tasks in all zones */
		flags |= VMUSAGE_ALL_TASKS;

	} else if (opts.o_outpmode & OPT_PROJECTS) {
		/*
		 * Gather rss for all projects in all zones.  Treat the same
		 * projid in diffrent zones as the same project.
		 */
		flags |= VMUSAGE_COL_PROJECTS;

	} else if (opts.o_outpmode & OPT_ZONES) {
		/* Gather rss for all zones */
		flags |= VMUSAGE_ALL_ZONES;

	} else {
		Die(gettext(
		    "Cannot determine rss flags for output options %x\n"),
		    opts.o_outpmode);
	}

	/*
	 * getvmusage() returns an array of result structures.  One for
	 * each zone, project, task, or user on the system, depending on
	 * flags.
	 *
	 * If getvmusage() fails, prstat will use the size already gathered
	 * from psinfo
	 */
	if (getvmusage(flags, opts.o_interval, NULL, &nres) != 0)
		return;

	results = (vmusage_t *)Malloc(sizeof (vmusage_t) * nres);
	for (;;) {
		ret = getvmusage(flags, opts.o_interval, results, &nres);
		if (ret == 0)
			break;
		if (errno == EOVERFLOW) {
			results = (vmusage_t *)Realloc(results,
			    sizeof (vmusage_t) * nres);
			continue;
		}
		/*
		 * Failure for some other reason.  Prstat will use the size
		 * already gathered from psinfo.
		 */
		free(results);
		return;
	}
	for (id = list->l_head; id != NULL; id = id->id_next) {

		match = NULL;
		next = results;
		for (i = 0; i < nres; i++, next++) {
			switch (flags) {
			case VMUSAGE_COL_RUSERS:
				if (next->vmu_id == id->id_uid)
					match = next;
				break;
			case VMUSAGE_ALL_TASKS:
				if (next->vmu_id == id->id_taskid)
					match = next;
				break;
			case VMUSAGE_COL_PROJECTS:
				if (next->vmu_id == id->id_projid)
					match = next;
				break;
			case VMUSAGE_ALL_ZONES:
				if (next->vmu_id == id->id_zoneid)
					match = next;
				break;
			default:
				Die(gettext(
				    "Unknown vmusage flags %d\n"), flags);
			}
		}
		if (match != NULL) {
			id->id_size = match->vmu_swap_all / 1024;
			id->id_rssize = match->vmu_rss_all / 1024;
			id->id_pctmem = (100.0 * (float)match->vmu_rss_all) /
			    (float)physmem;
			/* Output using data from getvmusage() */
			id->id_sizematch = B_TRUE;
		}
		/*
		 * If no match is found, prstat will use the size already
		 * gathered from psinfo.
		 */
	}
	free(results);
}

/*
 * A routine to display the contents of the list on the screen
 */
static void
list_print(list_t *list)
{
	lwp_info_t *lwp;
	id_info_t *id;
	char usr[4], sys[4], trp[4], tfl[4];
	char dfl[4], lck[4], slp[4], lat[4];
	char vcx[4], icx[4], scl[4], sig[4];
	char psize[6], prssize[6], pmem[6], pcpu[6], ptime[12];
	char pstate[7], pnice[4], ppri[4];
	char pname[LOGNAME_MAX+1];
	char projname[PROJNAME_MAX+1];
	char zonename[ZONENAME_MAX+1];
	float cpu, mem;
	double loadavg[3] = {0, 0, 0};
	int i, lwpid;

	if (list->l_size == 0)
		return;

	if (foreach_element(&set_tbl, &loadavg, psetloadavg) == 0) {
		/*
		 * If processor sets aren't specified, we display system-wide
		 * load averages.
		 */
		(void) getloadavg(loadavg, 3);
	}

	if (((opts.o_outpmode & OPT_UDATE) || (opts.o_outpmode & OPT_DDATE)) &&
	    ((list->l_type == LT_LWPS) || !(opts.o_outpmode & OPT_SPLIT)))
		print_timestamp();
	if (opts.o_outpmode & OPT_TTY)
		(void) putchar('\r');
	(void) putp(t_ulon);

	switch (list->l_type) {
	case LT_PROJECTS:
		if (opts.o_outpmode & OPT_LWPS)
			(void) printf(PROJECT_HEADER_LWP);
		else
			(void) printf(PROJECT_HEADER_PROC);
		break;
	case LT_TASKS:
		if (opts.o_outpmode & OPT_LWPS)
			(void) printf(TASK_HEADER_LWP);
		else
			(void) printf(TASK_HEADER_PROC);
		break;
	case LT_ZONES:
		if (opts.o_outpmode & OPT_LWPS)
			(void) printf(ZONE_HEADER_LWP);
		else
			(void) printf(ZONE_HEADER_PROC);
		break;
	case LT_USERS:
		if (opts.o_outpmode & OPT_LWPS)
			(void) printf(USER_HEADER_LWP);
		else
			(void) printf(USER_HEADER_PROC);
		break;
	case LT_LWPS:
		if (opts.o_outpmode & OPT_LWPS) {
			if (opts.o_outpmode & OPT_PSINFO) {
				if (opts.o_outpmode & OPT_LGRP)
					(void) printf(PSINFO_HEADER_LWP_LGRP);
				else
					(void) printf(PSINFO_HEADER_LWP);
			}
			if (opts.o_outpmode & OPT_MSACCT)
				(void) printf(USAGE_HEADER_LWP);
		} else {
			if (opts.o_outpmode & OPT_PSINFO) {
				if (opts.o_outpmode & OPT_LGRP)
					(void) printf(PSINFO_HEADER_PROC_LGRP);
				else
					(void) printf(PSINFO_HEADER_PROC);
			}
			if (opts.o_outpmode & OPT_MSACCT)
				(void) printf(USAGE_HEADER_PROC);
		}
		break;
	}

	(void) putp(t_uloff);
	(void) putp(t_eol);
	(void) putchar('\n');

	for (i = 0; i < list->l_used; i++) {
		switch (list->l_type) {
		case LT_PROJECTS:
		case LT_TASKS:
		case LT_USERS:
		case LT_ZONES:
			id = list->l_ptrs[i];
			/*
			 * CPU usage and memory usage normalization
			 */
			if (total_cpu >= 100)
				cpu = (100 * id->id_pctcpu) / total_cpu;
			else
				cpu = id->id_pctcpu;
			if (id->id_sizematch == B_FALSE && total_mem >= 100)
				mem = (100 * id->id_pctmem) / total_mem;
			else
				mem = id->id_pctmem;
			if (list->l_type == LT_USERS) {
				pwd_getname(id->id_uid, pname, sizeof (pname),
				    opts.o_outpmode & OPT_NORESOLVE,
				    opts.o_outpmode & (OPT_TERMCAP|OPT_TRUNC),
				    LOGIN_WIDTH);
			} else if (list->l_type == LT_ZONES) {
				getzonename(id->id_zoneid, zonename,
				    sizeof (zonename),
				    opts.o_outpmode & (OPT_TERMCAP|OPT_TRUNC),
				    ZONE_WIDTH);
			} else {
				getprojname(id->id_projid, projname,
				    sizeof (projname),
				    opts.o_outpmode & OPT_NORESOLVE,
				    opts.o_outpmode & (OPT_TERMCAP|OPT_TRUNC),
				    PROJECT_WIDTH);
			}
			Format_size(psize, id->id_size, 6);
			Format_size(prssize, id->id_rssize, 6);
			Format_pct(pmem, mem, 4);
			Format_pct(pcpu, cpu, 4);
			Format_time(ptime, id->id_time, 10);
			if (opts.o_outpmode & OPT_TTY)
				(void) putchar('\r');
			if (list->l_type == LT_PROJECTS)
				(void) printf(PROJECT_LINE, (int)id->id_projid,
				    id->id_nproc, psize, prssize, pmem, ptime,
				    pcpu, projname);
			else if (list->l_type == LT_TASKS)
				(void) printf(TASK_LINE, (int)id->id_taskid,
				    id->id_nproc, psize, prssize, pmem, ptime,
				    pcpu, projname);
			else if (list->l_type == LT_ZONES)
				(void) printf(ZONE_LINE, (int)id->id_zoneid,
				    id->id_nproc, psize, prssize, pmem, ptime,
				    pcpu, zonename);
			else
				(void) printf(USER_LINE, id->id_nproc, pname,
				    psize, prssize, pmem, ptime, pcpu);
			(void) putp(t_eol);
			(void) putchar('\n');
			break;
		case LT_LWPS:
			lwp = list->l_ptrs[i];
			if (opts.o_outpmode & OPT_LWPS)
				lwpid = lwp->li_info.pr_lwp.pr_lwpid;
			else
				lwpid = lwp->li_info.pr_nlwp +
				    lwp->li_info.pr_nzomb;
			pwd_getname(lwp->li_info.pr_uid, pname, sizeof (pname),
			    opts.o_outpmode & OPT_NORESOLVE,
			    opts.o_outpmode & (OPT_TERMCAP|OPT_TRUNC),
			    LOGIN_WIDTH);
			if (opts.o_outpmode & OPT_PSINFO) {
				Format_size(psize, lwp->li_info.pr_size, 6);
				Format_size(prssize, lwp->li_info.pr_rssize, 6);
				Format_state(pstate,
				    lwp->li_info.pr_lwp.pr_sname,
				    lwp->li_info.pr_lwp.pr_onpro, 7);
				if (strcmp(lwp->li_info.pr_lwp.pr_clname,
				    "RT") == 0 ||
				    strcmp(lwp->li_info.pr_lwp.pr_clname,
				    "SYS") == 0 ||
				    lwp->li_info.pr_lwp.pr_sname == 'Z')
					(void) strcpy(pnice, "  -");
				else
					Format_num(pnice,
					    lwp->li_info.pr_lwp.pr_nice - NZERO,
					    4);
				Format_num(ppri, lwp->li_info.pr_lwp.pr_pri, 4);
				Format_pct(pcpu,
				    FRC2PCT(lwp->li_info.pr_lwp.pr_pctcpu), 4);
				if (opts.o_outpmode & OPT_LWPS)
					Format_time(ptime,
					    lwp->li_info.pr_lwp.pr_time.tv_sec,
					    10);
				else
					Format_time(ptime,
					    lwp->li_info.pr_time.tv_sec, 10);
				if (opts.o_outpmode & OPT_TTY)
					(void) putchar('\r');
				stripfname(lwp->li_info.pr_fname);
				if (opts.o_outpmode & OPT_LGRP) {
					(void) printf(PSINFO_LINE_LGRP,
					    (int)lwp->li_info.pr_pid, pname,
					    psize, prssize, pstate,
					    ppri, pnice, ptime, pcpu,
					    (int)lwp->li_info.pr_lwp.pr_lgrp,
					    lwp->li_info.pr_fname, lwpid);
				} else {
					(void) printf(PSINFO_LINE,
					    (int)lwp->li_info.pr_pid, pname,
					    psize, prssize,
					    pstate, ppri, pnice,
					    ptime, pcpu,
					    lwp->li_info.pr_fname, lwpid);
				}
				(void) putp(t_eol);
				(void) putchar('\n');
			}
			if (opts.o_outpmode & OPT_MSACCT) {
				Format_pct(usr, lwp->li_usr, 4);
				Format_pct(sys, lwp->li_sys, 4);
				Format_pct(slp, lwp->li_slp, 4);
				Format_num(vcx, lwp->li_vcx, 4);
				Format_num(icx, lwp->li_icx, 4);
				Format_num(scl, lwp->li_scl, 4);
				Format_num(sig, lwp->li_sig, 4);
				Format_pct(trp, lwp->li_trp, 4);
				Format_pct(tfl, lwp->li_tfl, 4);
				Format_pct(dfl, lwp->li_dfl, 4);
				Format_pct(lck, lwp->li_lck, 4);
				Format_pct(lat, lwp->li_lat, 4);
				if (opts.o_outpmode & OPT_TTY)
					(void) putchar('\r');
				stripfname(lwp->li_info.pr_fname);
				(void) printf(USAGE_LINE,
				    (int)lwp->li_info.pr_pid, pname,
				    usr, sys, trp, tfl, dfl, lck,
				    slp, lat, vcx, icx, scl, sig,
				    lwp->li_info.pr_fname, lwpid);
				(void) putp(t_eol);
				(void) putchar('\n');
			}
			break;
		}
	}

	if (opts.o_outpmode & OPT_TTY)
		(void) putchar('\r');
	if (opts.o_outpmode & OPT_TERMCAP) {
		switch (list->l_type) {
		case LT_PROJECTS:
		case LT_USERS:
		case LT_TASKS:
		case LT_ZONES:
			while (i++ < opts.o_nbottom) {
				(void) putp(t_eol);
				(void) putchar('\n');
			}
			break;
		case LT_LWPS:
			while (i++ < opts.o_ntop) {
				(void) putp(t_eol);
				(void) putchar('\n');
			}
		}
	}

	if (opts.o_outpmode & OPT_TTY)
		(void) putchar('\r');

	if ((opts.o_outpmode & OPT_SPLIT) && list->l_type == LT_LWPS)
		return;

	(void) printf(TOTAL_LINE, total_procs, total_lwps,
	    loadavg[LOADAVG_1MIN], loadavg[LOADAVG_5MIN],
	    loadavg[LOADAVG_15MIN]);
	(void) putp(t_eol);
	(void) putchar('\n');
	if (opts.o_outpmode & OPT_TTY)
		(void) putchar('\r');
	(void) putp(t_eol);
	(void) fflush(stdout);
}

static lwp_info_t *
list_add_lwp(list_t *list, pid_t pid, id_t lwpid)
{
	lwp_info_t *lwp;

	if (list->l_head == NULL) {
		list->l_head = list->l_tail = lwp = Zalloc(sizeof (lwp_info_t));
	} else {
		lwp = Zalloc(sizeof (lwp_info_t));
		lwp->li_prev = list->l_tail;
		((lwp_info_t *)list->l_tail)->li_next = lwp;
		list->l_tail = lwp;
	}
	lwp->li_info.pr_pid = pid;
	lwp->li_info.pr_lwp.pr_lwpid = lwpid;
	lwpid_add(lwp, pid, lwpid);
	list->l_count++;
	return (lwp);
}

static void
list_remove_lwp(list_t *list, lwp_info_t *lwp)
{
	if (lwp->li_prev)
		lwp->li_prev->li_next = lwp->li_next;
	else
		list->l_head = lwp->li_next;	/* removing the head */
	if (lwp->li_next)
		lwp->li_next->li_prev = lwp->li_prev;
	else
		list->l_tail = lwp->li_prev;	/* removing the tail */
	lwpid_del(lwp->li_info.pr_pid, lwp->li_info.pr_lwp.pr_lwpid);
	if (lwpid_pidcheck(lwp->li_info.pr_pid) == 0)
		fds_rm(lwp->li_info.pr_pid);
	list->l_count--;
	free(lwp);
}

static void
list_clear(list_t *list)
{
	if (list->l_type == LT_LWPS) {
		lwp_info_t	*lwp = list->l_tail;
		lwp_info_t	*lwp_tmp;

		fd_closeall();
		while (lwp) {
			lwp_tmp = lwp;
			lwp = lwp->li_prev;
			list_remove_lwp(&lwps, lwp_tmp);
		}
	} else {
		id_info_t *id = list->l_head;
		id_info_t *nextid;

		while (id) {
			nextid = id->id_next;
			free(id);
			id = nextid;
		}
		list->l_count = 0;
		list->l_head = list->l_tail = NULL;
	}
}

static void
list_update(list_t *list, lwp_info_t *lwp)
{
	id_info_t *id;

	if (list->l_head == NULL) {			/* first element */
		list->l_head = list->l_tail = id = Zalloc(sizeof (id_info_t));
		goto update;
	}

	for (id = list->l_head; id; id = id->id_next) {
		if ((list->l_type == LT_USERS) &&
		    (id->id_uid != lwp->li_info.pr_uid))
			continue;
		if ((list->l_type == LT_TASKS) &&
		    (id->id_taskid != lwp->li_info.pr_taskid))
			continue;
		if ((list->l_type == LT_PROJECTS) &&
		    (id->id_projid != lwp->li_info.pr_projid))
			continue;
		if ((list->l_type == LT_ZONES) &&
		    (id->id_zoneid != lwp->li_info.pr_zoneid))
			continue;
		if ((list->l_type == LT_LGRPS) &&
		    (id->id_lgroup != lwp->li_info.pr_lwp.pr_lgrp))
			continue;
		id->id_nproc++;
		id->id_taskid	= lwp->li_info.pr_taskid;
		id->id_projid	= lwp->li_info.pr_projid;
		id->id_zoneid	= lwp->li_info.pr_zoneid;
		id->id_lgroup	= lwp->li_info.pr_lwp.pr_lgrp;

		if (lwp->li_flags & LWP_REPRESENT) {
			id->id_size	+= lwp->li_info.pr_size;
			id->id_rssize	+= lwp->li_info.pr_rssize;
		}
		id->id_pctcpu	+= FRC2PCT(lwp->li_info.pr_lwp.pr_pctcpu);
		if (opts.o_outpmode & OPT_LWPS)
			id->id_time += TIME2SEC(lwp->li_info.pr_lwp.pr_time);
		else
			id->id_time += TIME2SEC(lwp->li_info.pr_time);
		id->id_pctmem	+= FRC2PCT(lwp->li_info.pr_pctmem);
		id->id_key	+= lwp->li_key;
		total_cpu	+= FRC2PCT(lwp->li_info.pr_lwp.pr_pctcpu);
		total_mem	+= FRC2PCT(lwp->li_info.pr_pctmem);
		return;
	}

	id = list->l_tail;
	id->id_next = Zalloc(sizeof (id_info_t));
	id->id_next->id_prev = list->l_tail;
	id->id_next->id_next = NULL;
	list->l_tail = id->id_next;
	id = list->l_tail;
update:
	id->id_uid	= lwp->li_info.pr_uid;
	id->id_projid	= lwp->li_info.pr_projid;
	id->id_taskid	= lwp->li_info.pr_taskid;
	id->id_zoneid	= lwp->li_info.pr_zoneid;
	id->id_lgroup	= lwp->li_info.pr_lwp.pr_lgrp;
	id->id_nproc++;
	id->id_sizematch = B_FALSE;
	if (lwp->li_flags & LWP_REPRESENT) {
		id->id_size	= lwp->li_info.pr_size;
		id->id_rssize	= lwp->li_info.pr_rssize;
	}
	id->id_pctcpu	= FRC2PCT(lwp->li_info.pr_lwp.pr_pctcpu);
	if (opts.o_outpmode & OPT_LWPS)
		id->id_time = TIME2SEC(lwp->li_info.pr_lwp.pr_time);
	else
		id->id_time = TIME2SEC(lwp->li_info.pr_time);
	id->id_pctmem	= FRC2PCT(lwp->li_info.pr_pctmem);
	id->id_key	= lwp->li_key;
	total_cpu	+= id->id_pctcpu;
	total_mem	+= id->id_pctmem;
	list->l_count++;
}

static void
lwp_update(lwp_info_t *lwp, pid_t pid, id_t lwpid, struct prusage *usage)
{
	float period;

	if (!lwpid_is_active(pid, lwpid)) {
		/*
		 * If we are reading cpu times for the first time then
		 * calculate average cpu times based on whole process
		 * execution time.
		 */
		(void) memcpy(&lwp->li_usage, usage, sizeof (prusage_t));
		period = TIME2NSEC(usage->pr_rtime);
		period = period/(float)100;

		if (period == 0) { /* zombie */
			period = 1;
			lwp->li_usr = 0;
			lwp->li_sys = 0;
			lwp->li_slp = 0;
		} else {
			lwp->li_usr = TIME2NSEC(usage->pr_utime)/period;
			lwp->li_sys = TIME2NSEC(usage->pr_stime)/period;
			lwp->li_slp = TIME2NSEC(usage->pr_slptime)/period;
		}
		lwp->li_trp = TIME2NSEC(usage->pr_ttime)/period;
		lwp->li_tfl = TIME2NSEC(usage->pr_tftime)/period;
		lwp->li_dfl = TIME2NSEC(usage->pr_dftime)/period;
		lwp->li_lck = TIME2NSEC(usage->pr_ltime)/period;
		lwp->li_lat = TIME2NSEC(usage->pr_wtime)/period;
		period = (period / NANOSEC)*(float)100; /* now in seconds */
		lwp->li_vcx = (ulong_t)
		    (opts.o_interval * (usage->pr_vctx/period));
		lwp->li_icx = (ulong_t)
		    (opts.o_interval * (usage->pr_ictx/period));
		lwp->li_scl = (ulong_t)
		    (opts.o_interval * (usage->pr_sysc/period));
		lwp->li_sig = (ulong_t)
		    (opts.o_interval * (usage->pr_sigs/period));
		(void) lwpid_set_active(pid, lwpid);
	} else {
		/*
		 * If this is not a first time we are reading a process's
		 * CPU times then recalculate CPU times based on fresh data
		 * obtained from procfs and previous CPU time usage values.
		 */
		period = TIME2NSEC(usage->pr_rtime)-
		    TIME2NSEC(lwp->li_usage.pr_rtime);
		period = period/(float)100;

		if (period == 0) { /* zombie */
			period = 1;
			lwp->li_usr = 0;
			lwp->li_sys = 0;
			lwp->li_slp = 0;
		} else {
			lwp->li_usr = (TIME2NSEC(usage->pr_utime)-
			    TIME2NSEC(lwp->li_usage.pr_utime))/period;
			lwp->li_sys = (TIME2NSEC(usage->pr_stime) -
			    TIME2NSEC(lwp->li_usage.pr_stime))/period;
			lwp->li_slp = (TIME2NSEC(usage->pr_slptime) -
			    TIME2NSEC(lwp->li_usage.pr_slptime))/period;
		}
		lwp->li_trp = (TIME2NSEC(usage->pr_ttime) -
		    TIME2NSEC(lwp->li_usage.pr_ttime))/period;
		lwp->li_tfl = (TIME2NSEC(usage->pr_tftime) -
		    TIME2NSEC(lwp->li_usage.pr_tftime))/period;
		lwp->li_dfl = (TIME2NSEC(usage->pr_dftime) -
		    TIME2NSEC(lwp->li_usage.pr_dftime))/period;
		lwp->li_lck = (TIME2NSEC(usage->pr_ltime) -
		    TIME2NSEC(lwp->li_usage.pr_ltime))/period;
		lwp->li_lat = (TIME2NSEC(usage->pr_wtime) -
		    TIME2NSEC(lwp->li_usage.pr_wtime))/period;
		lwp->li_vcx = usage->pr_vctx - lwp->li_usage.pr_vctx;
		lwp->li_icx = usage->pr_ictx - lwp->li_usage.pr_ictx;
		lwp->li_scl = usage->pr_sysc - lwp->li_usage.pr_sysc;
		lwp->li_sig = usage->pr_sigs - lwp->li_usage.pr_sigs;
		(void) memcpy(&lwp->li_usage, usage, sizeof (prusage_t));
	}
}

static int
read_procfile(fd_t **fd, char *pidstr, char *file, void *buf, size_t bufsize)
{
	char procfile[MAX_PROCFS_PATH];

	(void) snprintf(procfile, MAX_PROCFS_PATH,
	    "/proc/%s/%s", pidstr, file);
	if ((*fd = fd_open(procfile, O_RDONLY, *fd)) == NULL)
		return (1);
	if (pread(fd_getfd(*fd), buf, bufsize, 0) != bufsize) {
		fd_close(*fd);
		return (1);
	}
	return (0);
}

static void
add_proc(psinfo_t *psinfo)
{
	lwp_info_t *lwp;
	id_t lwpid;
	pid_t pid = psinfo->pr_pid;

	lwpid = psinfo->pr_lwp.pr_lwpid;
	if ((lwp = lwpid_get(pid, lwpid)) == NULL)
		lwp = list_add_lwp(&lwps, pid, lwpid);
	lwp->li_flags |= LWP_ALIVE | LWP_REPRESENT;
	(void) memcpy(&lwp->li_info, psinfo, sizeof (psinfo_t));
	lwp->li_info.pr_lwp.pr_pctcpu = lwp->li_info.pr_pctcpu;
}

static void
add_lwp(psinfo_t *psinfo, lwpsinfo_t *lwpsinfo, int flags)
{
	lwp_info_t *lwp;
	pid_t pid = psinfo->pr_pid;
	id_t lwpid = lwpsinfo->pr_lwpid;

	if ((lwp = lwpid_get(pid, lwpid)) == NULL)
		lwp = list_add_lwp(&lwps, pid, lwpid);
	lwp->li_flags &= ~LWP_REPRESENT;
	lwp->li_flags |= LWP_ALIVE;
	lwp->li_flags |= flags;
	(void) memcpy(&lwp->li_info, psinfo,
	    sizeof (psinfo_t) - sizeof (lwpsinfo_t));
	(void) memcpy(&lwp->li_info.pr_lwp, lwpsinfo, sizeof (lwpsinfo_t));
}

static void
prstat_scandir(DIR *procdir)
{
	char *pidstr;
	pid_t pid;
	id_t lwpid;
	size_t entsz;
	long nlwps, nent, i;
	char *buf, *ptr;

	fds_t *fds;
	lwp_info_t *lwp;
	dirent_t *direntp;

	prheader_t	header;
	psinfo_t	psinfo;
	prusage_t	usage;
	lwpsinfo_t	*lwpsinfo;
	prusage_t	*lwpusage;

	total_procs = 0;
	total_lwps = 0;
	total_cpu = 0;
	total_mem = 0;

	convert_zone(&zone_tbl);
	for (rewinddir(procdir); (direntp = readdir(procdir)); ) {
		pidstr = direntp->d_name;
		if (pidstr[0] == '.')	/* skip "." and ".."  */
			continue;
		pid = atoi(pidstr);
		if (pid == 0 || pid == 2 || pid == 3)
			continue;	/* skip sched, pageout and fsflush */
		if (has_element(&pid_tbl, pid) == 0)
			continue;	/* check if we really want this pid */
		fds = fds_get(pid);	/* get ptr to file descriptors */

		if (read_procfile(&fds->fds_psinfo, pidstr,
		    "psinfo", &psinfo, sizeof (psinfo_t)) != 0)
			continue;
		if (!has_uid(&ruid_tbl, psinfo.pr_uid) ||
		    !has_uid(&euid_tbl, psinfo.pr_euid) ||
		    !has_element(&prj_tbl, psinfo.pr_projid) ||
		    !has_element(&tsk_tbl, psinfo.pr_taskid) ||
		    !has_zone(&zone_tbl, psinfo.pr_zoneid)) {
			fd_close(fds->fds_psinfo);
			continue;
		}
		nlwps = psinfo.pr_nlwp + psinfo.pr_nzomb;

		if (nlwps > 1 && (opts.o_outpmode & (OPT_LWPS | OPT_PSETS))) {
			int rep_lwp = 0;

			if (read_procfile(&fds->fds_lpsinfo, pidstr, "lpsinfo",
			    &header, sizeof (prheader_t)) != 0) {
				fd_close(fds->fds_psinfo);
				continue;
			}

			nent = header.pr_nent;
			entsz = header.pr_entsize * nent;
			ptr = buf = Malloc(entsz);
			if (pread(fd_getfd(fds->fds_lpsinfo), buf,
			    entsz, sizeof (struct prheader)) != entsz) {
				fd_close(fds->fds_lpsinfo);
				fd_close(fds->fds_psinfo);
				free(buf);
				continue;
			}

			nlwps = 0;
			for (i = 0; i < nent; i++, ptr += header.pr_entsize) {
				/*LINTED ALIGNMENT*/
				lwpsinfo = (lwpsinfo_t *)ptr;
				if (!has_element(&cpu_tbl,
				    lwpsinfo->pr_onpro) ||
				    !has_element(&set_tbl,
				    lwpsinfo->pr_bindpset) ||
				    !has_element(&lgr_tbl, lwpsinfo->pr_lgrp))
					continue;
				nlwps++;
				if ((opts.o_outpmode & (OPT_PSETS | OPT_LWPS))
				    == OPT_PSETS) {
					/*
					 * If one of process's LWPs is bound
					 * to a given processor set, report the
					 * whole process.  We may be doing this
					 * a few times but we'll get an accurate
					 * lwp count in return.
					 */
					add_proc(&psinfo);
				} else {
					if (rep_lwp == 0) {
						rep_lwp = 1;
						add_lwp(&psinfo, lwpsinfo,
						    LWP_REPRESENT);
					} else {
						add_lwp(&psinfo, lwpsinfo, 0);
					}
				}
			}
			free(buf);
			if (nlwps == 0) {
				fd_close(fds->fds_lpsinfo);
				fd_close(fds->fds_psinfo);
				continue;
			}
		} else {
			if (!has_element(&cpu_tbl, psinfo.pr_lwp.pr_onpro) ||
			    !has_element(&set_tbl, psinfo.pr_lwp.pr_bindpset) ||
			    !has_element(&lgr_tbl, psinfo.pr_lwp.pr_lgrp)) {
				fd_close(fds->fds_psinfo);
				continue;
			}
			add_proc(&psinfo);
		}
		if (!(opts.o_outpmode & OPT_MSACCT)) {
			total_procs++;
			total_lwps += nlwps;
			continue;
		}
		/*
		 * Get more information about processes from /proc/pid/usage.
		 * If process has more than one lwp, then we may have to
		 * also look at the /proc/pid/lusage file.
		 */
		if ((opts.o_outpmode & OPT_LWPS) && (nlwps > 1)) {
			if (read_procfile(&fds->fds_lusage, pidstr, "lusage",
			    &header, sizeof (prheader_t)) != 0) {
				fd_close(fds->fds_lpsinfo);
				fd_close(fds->fds_psinfo);
				continue;
			}
			nent = header.pr_nent;
			entsz = header.pr_entsize * nent;
			buf = Malloc(entsz);
			if (pread(fd_getfd(fds->fds_lusage), buf,
			    entsz, sizeof (struct prheader)) != entsz) {
				fd_close(fds->fds_lusage);
				fd_close(fds->fds_lpsinfo);
				fd_close(fds->fds_psinfo);
				free(buf);
				continue;
			}
			for (i = 1, ptr = buf + header.pr_entsize; i < nent;
			    i++, ptr += header.pr_entsize) {
				/*LINTED ALIGNMENT*/
				lwpusage = (prusage_t *)ptr;
				lwpid = lwpusage->pr_lwpid;
				/*
				 * New LWPs created after we read lpsinfo
				 * will be ignored.  Don't want to do
				 * everything all over again.
				 */
				if ((lwp = lwpid_get(pid, lwpid)) == NULL)
					continue;
				lwp_update(lwp, pid, lwpid, lwpusage);
			}
			free(buf);
		} else {
			if (read_procfile(&fds->fds_usage, pidstr, "usage",
			    &usage, sizeof (prusage_t)) != 0) {
				fd_close(fds->fds_lpsinfo);
				fd_close(fds->fds_psinfo);
				continue;
			}
			lwpid = psinfo.pr_lwp.pr_lwpid;
			if ((lwp = lwpid_get(pid, lwpid)) == NULL)
				continue;
			lwp_update(lwp, pid, lwpid, &usage);
		}
		total_procs++;
		total_lwps += nlwps;
	}
	fd_update();
}

/*
 * This procedure removes all dead lwps from the linked list of all lwps.
 * It also creates linked list of ids if necessary.
 */
static void
list_refresh(list_t *list)
{
	lwp_info_t *lwp, *lwp_next;

	if (!(list->l_type & LT_LWPS))
		return;

	for (lwp = list->l_head; lwp != NULL; ) {
		if (lwp->li_flags & LWP_ALIVE) {
			/*
			 * Process all live LWPs.
			 * When we're done, mark them as dead.
			 * They will be marked "alive" on the next
			 * /proc scan if they still exist.
			 */
			lwp->li_key = list_getkeyval(list, lwp);
			if (opts.o_outpmode & OPT_USERS)
				list_update(&users, lwp);
			if (opts.o_outpmode & OPT_TASKS)
				list_update(&tasks, lwp);
			if (opts.o_outpmode & OPT_PROJECTS)
				list_update(&projects, lwp);
			if (opts.o_outpmode & OPT_ZONES)
				list_update(&zones, lwp);
			if (opts.o_outpmode & OPT_LGRP)
				list_update(&lgroups, lwp);
			lwp->li_flags &= ~LWP_ALIVE;
			lwp = lwp->li_next;

		} else {
			lwp_next = lwp->li_next;
			list_remove_lwp(&lwps, lwp);
			lwp = lwp_next;
		}
	}
}

static void
curses_on()
{
	if ((opts.o_outpmode & OPT_TERMCAP) && (is_curses_on == FALSE)) {
		(void) initscr();
		(void) nonl();
		(void) putp(t_smcup);
		is_curses_on = TRUE;
	}
}

static void
curses_off()
{
	if ((is_curses_on == TRUE) && (opts.o_outpmode & OPT_TERMCAP)) {
		(void) putp(t_rmcup);
		(void) endwin();
		is_curses_on = FALSE;
	}
	(void) fflush(stdout);
}

static int
nlines()
{
	struct winsize ws;
	char *envp;
	int n;
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != -1) {
		if (ws.ws_row > 0)
			return (ws.ws_row);
	}
	if (envp = getenv("LINES")) {
		if ((n = Atoi(envp)) > 0) {
			opts.o_outpmode &= ~OPT_USEHOME;
			return (n);
		}
	}
	return (-1);
}

static void
setmovecur()
{
	int i, n;
	if ((opts.o_outpmode & OPT_FULLSCREEN) &&
	    (opts.o_outpmode & OPT_USEHOME)) {
		movecur = t_home;
		return;
	}
	if (opts.o_outpmode & OPT_SPLIT) {
		if (opts.o_ntop == 0)
			n = opts.o_nbottom + 1;
		else
			n = opts.o_ntop + opts.o_nbottom + 2;
	} else {
		if (opts.o_outpmode & OPT_USERS)
			n = opts.o_nbottom + 1;
		else
			n = opts.o_ntop + 1;
	}
	if (((opts.o_outpmode & OPT_UDATE) || (opts.o_outpmode & OPT_DDATE)))
		n++;

	if (movecur != NULL && movecur != empty_string && movecur != t_home)
		free(movecur);
	movecur = Zalloc(strlen(t_up) * (n + 5));
	for (i = 0; i <= n; i++)
		(void) strcat(movecur, t_up);
}

static int
setsize()
{
	static int oldn = 0;
	int n;

	if (opts.o_outpmode & OPT_FULLSCREEN) {
		n = nlines();
		if (n == oldn)
			return (0);
		oldn = n;
		if (n == -1) {
			opts.o_outpmode &= ~OPT_USEHOME;
			setmovecur();		/* set default window size */
			return (1);
		}
		n = n - 3;	/* minus header, total and cursor lines */
		if ((opts.o_outpmode & OPT_UDATE) ||
		    (opts.o_outpmode & OPT_DDATE))
			n--;	/* minus timestamp */
		if (n < 1)
			Die(gettext("window is too small (try -n)\n"));
		if (opts.o_outpmode & OPT_SPLIT) {
			if (n < 8) {
				Die(gettext("window is too small (try -n)\n"));
			} else {
				opts.o_ntop = (n / 4) * 3;
				opts.o_nbottom = n - 1 - opts.o_ntop;
			}
		} else {
			if (opts.o_outpmode & OPT_USERS)
				opts.o_nbottom = n;
			else
				opts.o_ntop = n;
		}
	}
	setmovecur();
	return (1);
}

static void
ldtermcap()
{
	int err;
	if (setupterm(NULL, STDIN_FILENO, &err) == ERR) {
		switch (err) {
		case 0:
			Warn(gettext("failed to load terminal info, "
			    "defaulting to -c option\n"));
			break;
		case -1:
			Warn(gettext("terminfo database not found, "
			    "defaulting to -c option\n"));
			break;
		default:
			Warn(gettext("failed to initialize terminal, "
			    "defaulting to -c option\n"));
		}
		opts.o_outpmode &= ~OPT_TERMCAP;
		t_up = t_eol = t_smcup = t_rmcup = movecur = empty_string;
		t_ulon = t_uloff = empty_string;
		return;
	}
	t_ulon	= tigetstr("smul");
	t_uloff	= tigetstr("rmul");
	t_up	= tigetstr("cuu1");
	t_eol	= tigetstr("el");
	t_smcup	= tigetstr("smcup");
	t_rmcup = tigetstr("rmcup");
	t_home  = tigetstr("home");
	if ((t_up == (char *)-1) || (t_eol == (char *)-1) ||
	    (t_smcup == (char *)-1) || (t_rmcup == (char *)-1)) {
		opts.o_outpmode &= ~OPT_TERMCAP;
		t_up = t_eol = t_smcup = t_rmcup = movecur = empty_string;
		return;
	}
	if (t_up == NULL || t_eol == NULL) {
		opts.o_outpmode &= ~OPT_TERMCAP;
		t_eol = t_up = movecur = empty_string;
		return;
	}
	if (t_ulon == (char *)-1 || t_uloff == (char *)-1 ||
	    t_ulon == NULL || t_uloff == NULL) {
		t_ulon = t_uloff = empty_string;  /* can live without it */
	}
	if (t_smcup == NULL || t_rmcup == NULL)
		t_smcup = t_rmcup = empty_string;
	if (t_home == (char *)-1 || t_home == NULL) {
		opts.o_outpmode &= ~OPT_USEHOME;
		t_home = empty_string;
	}
}

static void
sig_handler(int sig)
{
	switch (sig) {
	case SIGTSTP:	sigtstp = 1;
			break;
	case SIGWINCH:	sigwinch = 1;
			break;
	case SIGINT:
	case SIGTERM:	sigterm = 1;
			break;
	}
}

static void
set_signals()
{
	(void) signal(SIGTSTP, sig_handler);
	(void) signal(SIGINT, sig_handler);
	(void) signal(SIGTERM, sig_handler);
	if (opts.o_outpmode & OPT_FULLSCREEN)
		(void) signal(SIGWINCH, sig_handler);
}

static void
fill_table(table_t *table, char *arg, char option)
{
	char *p = strtok(arg, ", ");

	if (p == NULL)
		Die(gettext("invalid argument for -%c\n"), option);

	add_element(table, (long)Atoi(p));
	while (p = strtok(NULL, ", "))
		add_element(table, (long)Atoi(p));
}

static void
fill_prj_table(char *arg)
{
	projid_t projid;
	char *p = strtok(arg, ", ");

	if (p == NULL)
		Die(gettext("invalid argument for -j\n"));

	if ((projid = getprojidbyname(p)) == -1)
		projid = Atoi(p);
	add_element(&prj_tbl, (long)projid);

	while (p = strtok(NULL, ", ")) {
		if ((projid = getprojidbyname(p)) == -1)
			projid = Atoi(p);
		add_element(&prj_tbl, (long)projid);
	}
}

static void
fill_set_table(char *arg)
{
	char *p = strtok(arg, ", ");
	psetid_t id;

	if (p == NULL)
		Die(gettext("invalid argument for -C\n"));

	if ((id = Atoi(p)) == 0)
		id = PS_NONE;
	add_element(&set_tbl, id);
	while (p = strtok(NULL, ", ")) {
		if ((id = Atoi(p)) == 0)
			id = PS_NONE;
		if (!has_element(&set_tbl, id))
			add_element(&set_tbl, id);
	}
}

static void
Exit()
{
	curses_off();
	list_clear(&lwps);
	list_clear(&users);
	list_clear(&tasks);
	list_clear(&projects);
	list_clear(&zones);
	fd_exit();
}


int
main(int argc, char **argv)
{
	DIR *procdir;
	char *p;
	char *sortk = "cpu";	/* default sort key */
	int opt;
	int timeout;
	struct pollfd pollset;
	char key;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	Progname(argv[0]);
	lwpid_init();
	fd_init(Setrlimit());

	pagesize = sysconf(_SC_PAGESIZE);

	while ((opt = getopt(argc, argv,
	    "vcd:HmarRLtu:U:n:p:C:P:h:s:S:j:k:TJWz:Z")) != (int)EOF) {
		switch (opt) {
		case 'r':
			opts.o_outpmode |= OPT_NORESOLVE;
			break;
		case 'R':
			opts.o_outpmode |= OPT_REALTIME;
			break;
		case 'c':
			opts.o_outpmode &= ~OPT_TERMCAP;
			opts.o_outpmode &= ~OPT_FULLSCREEN;
			break;
		case 'd':
			if (optarg) {
				if (*optarg == 'u')
					opts.o_outpmode |= OPT_UDATE;
				else if (*optarg == 'd')
					opts.o_outpmode |= OPT_DDATE;
				else
					Usage();
			} else {
				Usage();
			}
			break;
		case 'h':
			fill_table(&lgr_tbl, optarg, 'h');
			break;
		case 'H':
			opts.o_outpmode |= OPT_LGRP;
			break;
		case 'm':
		case 'v':
			opts.o_outpmode &= ~OPT_PSINFO;
			opts.o_outpmode |=  OPT_MSACCT;
			break;
		case 't':
			opts.o_outpmode &= ~OPT_PSINFO;
			opts.o_outpmode |= OPT_USERS;
			break;
		case 'a':
			opts.o_outpmode |= OPT_SPLIT | OPT_USERS;
			break;
		case 'T':
			opts.o_outpmode |= OPT_SPLIT | OPT_TASKS;
			break;
		case 'J':
			opts.o_outpmode |= OPT_SPLIT | OPT_PROJECTS;
			break;
		case 'n':
			if ((p = strtok(optarg, ",")) == NULL)
				Die(gettext("invalid argument for -n\n"));
			opts.o_ntop = Atoi(p);
			if (p = strtok(NULL, ","))
				opts.o_nbottom = Atoi(p);
			else if (opts.o_ntop == 0)
				opts.o_nbottom = 5;
			opts.o_outpmode &= ~OPT_FULLSCREEN;
			break;
		case 's':
			opts.o_sortorder = -1;
			sortk = optarg;
			break;
		case 'S':
			opts.o_sortorder = 1;
			sortk = optarg;
			break;
		case 'u':
			if ((p = strtok(optarg, ", ")) == NULL)
				Die(gettext("invalid argument for -u\n"));
			add_uid(&euid_tbl, p);
			while (p = strtok(NULL, ", "))
				add_uid(&euid_tbl, p);
			break;
		case 'U':
			if ((p = strtok(optarg, ", ")) == NULL)
				Die(gettext("invalid argument for -U\n"));
			add_uid(&ruid_tbl, p);
			while (p = strtok(NULL, ", "))
				add_uid(&ruid_tbl, p);
			break;
		case 'p':
			fill_table(&pid_tbl, optarg, 'p');
			break;
		case 'C':
			fill_set_table(optarg);
			opts.o_outpmode |= OPT_PSETS;
			break;
		case 'P':
			fill_table(&cpu_tbl, optarg, 'P');
			break;
		case 'k':
			fill_table(&tsk_tbl, optarg, 'k');
			break;
		case 'j':
			fill_prj_table(optarg);
			break;
		case 'L':
			opts.o_outpmode |= OPT_LWPS;
			break;
		case 'W':
			opts.o_outpmode |= OPT_TRUNC;
			break;
		case 'z':
			if ((p = strtok(optarg, ", ")) == NULL)
				Die(gettext("invalid argument for -z\n"));
			add_zone(&zone_tbl, p);
			while (p = strtok(NULL, ", "))
				add_zone(&zone_tbl, p);
			break;
		case 'Z':
			opts.o_outpmode |= OPT_SPLIT | OPT_ZONES;
			break;
		default:
			Usage();
		}
	}

	(void) atexit(Exit);
	if ((opts.o_outpmode & OPT_USERS) &&
	    !(opts.o_outpmode & OPT_SPLIT))
		opts.o_nbottom = opts.o_ntop;
	if (!(opts.o_outpmode & OPT_SPLIT) && opts.o_ntop == 0)
		Die(gettext("invalid argument for -n\n"));
	if (opts.o_nbottom == 0)
		Die(gettext("invalid argument for -n\n"));
	if (!(opts.o_outpmode & OPT_SPLIT) && (opts.o_outpmode & OPT_USERS) &&
	    ((opts.o_outpmode & (OPT_PSINFO | OPT_MSACCT))))
		Die(gettext("-t option cannot be used with -v or -m\n"));

	if ((opts.o_outpmode & OPT_SPLIT) && (opts.o_outpmode & OPT_USERS) &&
	    !((opts.o_outpmode & (OPT_PSINFO | OPT_MSACCT))))
		Die(gettext("-t option cannot be used with "
		    "-a, -J, -T or -Z\n"));

	if ((opts.o_outpmode & OPT_USERS) &&
	    (opts.o_outpmode & (OPT_TASKS | OPT_PROJECTS | OPT_ZONES)))
		Die(gettext("-a option cannot be used with "
		    "-t, -J, -T or -Z\n"));

	if (((opts.o_outpmode & OPT_TASKS) &&
	    (opts.o_outpmode & (OPT_PROJECTS|OPT_ZONES))) ||
	    ((opts.o_outpmode & OPT_PROJECTS) &&
	    (opts.o_outpmode & (OPT_TASKS|OPT_ZONES)))) {
		Die(gettext(
		    "-J, -T and -Z options are mutually exclusive\n"));
	}

	/*
	 * There is not enough space to combine microstate information and
	 * lgroup information and still fit in 80-column output.
	 */
	if ((opts.o_outpmode & OPT_LGRP) && (opts.o_outpmode & OPT_MSACCT)) {
		Die(gettext("-H and -m options are mutually exclusive\n"));
	}

	if (argc > optind)
		opts.o_interval = Atoi(argv[optind++]);
	if (argc > optind)
		opts.o_count = Atoi(argv[optind++]);
	if (opts.o_count == 0)
		Die(gettext("invalid counter value\n"));
	if (argc > optind)
		Usage();
	if (opts.o_outpmode & OPT_REALTIME)
		Priocntl("RT");
	if (isatty(STDOUT_FILENO) == 1 && isatty(STDIN_FILENO))
		opts.o_outpmode |= OPT_TTY;	/* interactive */
	if (!(opts.o_outpmode & OPT_TTY)) {
		opts.o_outpmode &= ~OPT_TERMCAP; /* no termcap for pipes */
		opts.o_outpmode &= ~OPT_FULLSCREEN;
	}
	if (opts.o_outpmode & OPT_TERMCAP)
		ldtermcap();		/* can turn OPT_TERMCAP off */
	if (opts.o_outpmode & OPT_TERMCAP)
		(void) setsize();
	list_alloc(&lwps, opts.o_ntop);
	list_alloc(&users, opts.o_nbottom);
	list_alloc(&tasks, opts.o_nbottom);
	list_alloc(&projects, opts.o_nbottom);
	list_alloc(&zones, opts.o_nbottom);
	list_alloc(&lgroups, opts.o_nbottom);
	list_setkeyfunc(sortk, &opts, &lwps, LT_LWPS);
	list_setkeyfunc(NULL, &opts, &users, LT_USERS);
	list_setkeyfunc(NULL, &opts, &tasks, LT_TASKS);
	list_setkeyfunc(NULL, &opts, &projects, LT_PROJECTS);
	list_setkeyfunc(NULL, &opts, &zones, LT_ZONES);
	list_setkeyfunc(NULL, &opts, &lgroups, LT_LGRPS);
	if (opts.o_outpmode & OPT_TERMCAP)
		curses_on();
	if ((procdir = opendir("/proc")) == NULL)
		Die(gettext("cannot open /proc directory\n"));
	if (opts.o_outpmode & OPT_TTY) {
		(void) printf(gettext("Please wait...\r"));
		if (!(opts.o_outpmode & OPT_TERMCAP))
			(void) putchar('\n');
		(void) fflush(stdout);
	}
	set_signals();
	pollset.fd = STDIN_FILENO;
	pollset.events = POLLIN;
	timeout = opts.o_interval * MILLISEC;

	/*
	 * main program loop
	 */
	do {
		if (sigterm == 1)
			break;
		if (sigtstp == 1) {
			curses_off();
			(void) signal(SIGTSTP, SIG_DFL);
			(void) kill(0, SIGTSTP);
			/*
			 * prstat stops here until it receives SIGCONT signal.
			 */
			sigtstp = 0;
			(void) signal(SIGTSTP, sig_handler);
			curses_on();
			print_movecur = FALSE;
			if (opts.o_outpmode & OPT_FULLSCREEN)
				sigwinch = 1;
		}
		if (sigwinch == 1) {
			if (setsize() == 1) {
				list_free(&lwps);
				list_free(&users);
				list_free(&tasks);
				list_free(&projects);
				list_free(&zones);
				list_alloc(&lwps, opts.o_ntop);
				list_alloc(&users, opts.o_nbottom);
				list_alloc(&tasks, opts.o_nbottom);
				list_alloc(&projects, opts.o_nbottom);
				list_alloc(&zones, opts.o_nbottom);
			}
			sigwinch = 0;
			(void) signal(SIGWINCH, sig_handler);
		}
		prstat_scandir(procdir);
		list_refresh(&lwps);
		if (print_movecur)
			(void) putp(movecur);
		print_movecur = TRUE;
		if ((opts.o_outpmode & OPT_PSINFO) ||
		    (opts.o_outpmode & OPT_MSACCT)) {
			list_sort(&lwps);
			list_print(&lwps);
		}
		if (opts.o_outpmode & OPT_USERS) {
			list_getsize(&users);
			list_sort(&users);
			list_print(&users);
			list_clear(&users);
		}
		if (opts.o_outpmode & OPT_TASKS) {
			list_getsize(&tasks);
			list_sort(&tasks);
			list_print(&tasks);
			list_clear(&tasks);
		}
		if (opts.o_outpmode & OPT_PROJECTS) {
			list_getsize(&projects);
			list_sort(&projects);
			list_print(&projects);
			list_clear(&projects);
		}
		if (opts.o_outpmode & OPT_ZONES) {
			list_getsize(&zones);
			list_sort(&zones);
			list_print(&zones);
			list_clear(&zones);
		}
		if (opts.o_count == 1)
			break;
		/*
		 * If poll() returns -1 and sets errno to EINTR here because
		 * the process received a signal, it is Ok to abort this
		 * timeout and loop around because we check the signals at the
		 * top of the loop.
		 */
		if (opts.o_outpmode & OPT_TTY) {
			if (poll(&pollset, (nfds_t)1, timeout) > 0) {
				if (read(STDIN_FILENO, &key, 1) == 1) {
					if (tolower(key) == 'q')
						break;
				}
			}
		} else {
			(void) sleep(opts.o_interval);
		}
	} while (opts.o_count == (-1) || --opts.o_count);

	if (opts.o_outpmode & OPT_TTY)
		(void) putchar('\r');
	return (0);
}
