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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Joyent, Inc.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/tuneable.h>
#include <sys/errno.h>
#include <sys/var.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <sys/sysconfig.h>
#include <sys/resource.h>
#include <sys/ulimit.h>
#include <sys/unistd.h>
#include <sys/debug.h>
#include <sys/cpuvar.h>
#include <sys/mman.h>
#include <sys/timer.h>
#include <sys/zone.h>
#include <sys/vm_usage.h>

extern rctl_hndl_t rc_process_sigqueue;

long
sysconfig(int which)
{
	switch (which) {

	/*
	 * if it is not handled in mach_sysconfig either
	 * it must be EINVAL.
	 */
	default:
		return (mach_sysconfig(which)); /* `uname -i`/os */

	case _CONFIG_CLK_TCK:
		return ((long)hz);	/* clock frequency per second */

	case _CONFIG_PROF_TCK:
		return ((long)hz);	/* profiling clock freq per sec */

	case _CONFIG_NGROUPS:
		/*
		 * Maximum number of supplementary groups.
		 */
		return (ngroups_max);

	case _CONFIG_OPEN_FILES:
		/*
		 * Maximum number of open files (soft limit).
		 */
		{
			rlim64_t fd_ctl;
			mutex_enter(&curproc->p_lock);
			fd_ctl = rctl_enforced_value(
			    rctlproc_legacy[RLIMIT_NOFILE], curproc->p_rctls,
			    curproc);
			mutex_exit(&curproc->p_lock);
			return ((ulong_t)fd_ctl);
		}

	case _CONFIG_CHILD_MAX:
		/*
		 * Maximum number of processes.
		 */
		return (v.v_maxup);

	case _CONFIG_POSIX_VER:
		return (_POSIX_VERSION); /* current POSIX version */

	case _CONFIG_PAGESIZE:
		return (PAGESIZE);

	case _CONFIG_XOPEN_VER:
		return (_XOPEN_VERSION); /* current XOPEN version */

	case _CONFIG_NPROC_CONF:
		return (zone_ncpus_get(curproc->p_zone));

	case _CONFIG_NPROC_ONLN:
		return (zone_ncpus_online_get(curproc->p_zone));

	case _CONFIG_NPROC_MAX:
		return (max_ncpus);

	case _CONFIG_NPROC_NCPU:
		return (NCPU); /* Private sysconfig for direct NCPU access */

	case _CONFIG_STACK_PROT:
		return (curproc->p_stkprot & ~PROT_USER);

	case _CONFIG_AIO_LISTIO_MAX:
		return (_AIO_LISTIO_MAX);

	case _CONFIG_AIO_MAX:
		return (_AIO_MAX);

	case _CONFIG_AIO_PRIO_DELTA_MAX:
		return (0);

	case _CONFIG_DELAYTIMER_MAX:
		return (INT_MAX);

	case _CONFIG_MQ_OPEN_MAX:
		return (_MQ_OPEN_MAX);

	case _CONFIG_MQ_PRIO_MAX:
		return (_MQ_PRIO_MAX);

	case _CONFIG_RTSIG_MAX:
		return (_SIGRTMAX - _SIGRTMIN + 1);

	case _CONFIG_SEM_NSEMS_MAX:
		return (_SEM_NSEMS_MAX);

	case _CONFIG_SEM_VALUE_MAX:
		return (_SEM_VALUE_MAX);

	case _CONFIG_SIGQUEUE_MAX:
		/*
		 * Maximum number of outstanding queued signals.
		 */
		{
			rlim64_t sigqsz_max;
			mutex_enter(&curproc->p_lock);
			sigqsz_max = rctl_enforced_value(rc_process_sigqueue,
			    curproc->p_rctls, curproc);
			mutex_exit(&curproc->p_lock);
			return ((uint_t)sigqsz_max);
		}

	case _CONFIG_SIGRT_MIN:
		return (_SIGRTMIN);

	case _CONFIG_SIGRT_MAX:
		return (_SIGRTMAX);

	case _CONFIG_TIMER_MAX:
		return (timer_max);

	case _CONFIG_PHYS_PAGES:
		/*
		 * If the non-global zone has a phys. memory cap, use that.
		 * We always report the system-wide value for the global zone,
		 * even though rcapd can be used on the global zone too.
		 */
		if (!INGLOBALZONE(curproc) &&
		    curproc->p_zone->zone_phys_mem_ctl != UINT64_MAX)
			return (MIN(btop(curproc->p_zone->zone_phys_mem_ctl),
			    physinstalled));

		return (physinstalled);

	case _CONFIG_AVPHYS_PAGES:
		/*
		 * If the non-global zone has a phys. memory cap, use
		 * the phys. memory cap - zone's rss.  We always
		 * report the system-wide value for the global zone, even
		 * though memory capping can be used on the global zone too.
		 * We use the cached value for the RSS since vm_getusage()
		 * is so expensive and we don't need this value to be exact.
		 */
		if (!INGLOBALZONE(curproc) &&
		    curproc->p_zone->zone_phys_mem_ctl != UINT64_MAX) {
			pgcnt_t cap, rss, free;

			cap = btop(curproc->p_zone->zone_phys_mem_ctl);
			if (cap > physinstalled)
				return (freemem);

			rss = btop(curproc->p_zone->zone_phys_mem);
			/*
			 * Because this is a soft cap, it is possible
			 * for rss to be temporarily over the cap.
			 */
			if (cap > rss)
				free = cap - rss;
			else
				free = 0;
			return (MIN(free, freemem));
		}

		return (freemem);

	case _CONFIG_MAXPID:
		return (maxpid);

	case _CONFIG_CPUID_MAX:
		return (max_cpuid);

	case _CONFIG_EPHID_MAX:
		return (MAXEPHUID);

	case _CONFIG_SYMLOOP_MAX:
		return (MAXSYMLINKS);
	}
}
