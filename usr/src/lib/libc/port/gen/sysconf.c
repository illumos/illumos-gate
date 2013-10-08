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
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/* sysconf(3C) - returns system configuration information */

#pragma weak _sysconf = sysconf

#include "lint.h"
#include <mtlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/sysconfig.h>
#include <limits.h>
#include <time.h>
#include <errno.h>
#include <nss_dbdefs.h>
#include <thread.h>
#include <xti.h>
#include "libc.h"
#include "xpg6.h"

/* from nss_common.c */
extern size_t _nss_get_bufsizes(int);

long
sysconf(int name)
{
	static int _pagesize = 0;
	static int _hz = 0;
	static pid_t _maxpid = 0;
	static int _stackprot = 0;
	static int _ngroups_max;
	extern int __xpg4;

	switch (name) {
		default:
			errno = EINVAL;
			return (-1L);

		case _SC_ARG_MAX:
			return ((long)ARG_MAX);

		case _SC_CLK_TCK:
			if (_hz <= 0)
				_hz = _sysconfig(_CONFIG_CLK_TCK);
			return (_hz);

		case _SC_JOB_CONTROL:
			return ((long)_POSIX_JOB_CONTROL);

		case _SC_SAVED_IDS:
			return ((long)_POSIX_SAVED_IDS);

		case _SC_CHILD_MAX:
			return (_sysconfig(_CONFIG_CHILD_MAX));

		case _SC_NGROUPS_MAX:
			if (_ngroups_max <= 0)
				_ngroups_max = _sysconfig(_CONFIG_NGROUPS);
			return (_ngroups_max);

		case _SC_OPEN_MAX:
			return (_sysconfig(_CONFIG_OPEN_FILES));

		case _SC_VERSION:
			if (__xpg6 & _C99SUSv3_XPG6_sysconf_version)
				return (200112L);
			else
				return (199506L);

		case _SC_PAGESIZE:
			if (_pagesize <= 0)
				_pagesize = _sysconfig(_CONFIG_PAGESIZE);
			return (_pagesize);

		case _SC_XOPEN_VERSION:
			if (__xpg6 & _C99SUSv3_XPG6_sysconf_version)
				return (600L);
			else if (__xpg4 == 0)
				return (_sysconfig(_CONFIG_XOPEN_VER));
			else
				return (4L);

		case _SC_XOPEN_XCU_VERSION:
			if (__xpg6 & _C99SUSv3_XPG6_sysconf_version)
				return (600L);
			else
				return (4L);

		/*
		 * old value for pre XPG5 conformant systems to match
		 * getpass() length.
		 * XPG5 special cased with __sysconf_xpg5()
		 * new value for default and modern XPG systems.
		 */
		case _SC_PASS_MAX:
			if ((__xpg4 == 1) &&
			    (!(__xpg6 & _C99SUSv3_XPG6_sysconf_version)))
				return ((long)_PASS_MAX_XPG);
			else
				return ((long)_PASS_MAX);

		case _SC_LOGNAME_MAX:
			return ((long)LOGNAME_MAX);

		case _SC_STREAM_MAX:
			return (_sysconfig(_CONFIG_OPEN_FILES));

		case _SC_TZNAME_MAX:
			return (-1L);

		case _SC_NPROCESSORS_CONF:
			return (_sysconfig(_CONFIG_NPROC_CONF));

		case _SC_NPROCESSORS_ONLN:
			return (_sysconfig(_CONFIG_NPROC_ONLN));

		case _SC_NPROCESSORS_MAX:
			return (_sysconfig(_CONFIG_NPROC_MAX));

		case _SC_STACK_PROT:
			if (_stackprot == 0)
				_stackprot = _sysconfig(_CONFIG_STACK_PROT);
			return (_stackprot);

		/* POSIX.4 names */

		/*
		 * Each of the following also have _POSIX_* symbols
		 * defined in <unistd.h>. Values here should align
		 * with values in the header. Up until the SUSv3 standard
		 * we defined these simply as 1. With the introduction
		 * of the new revision, these were changed to 200112L.
		 * The standard allows us to change the value, however,
		 * we have kept both values in case application programs
		 * are relying on the previous value even though an
		 * application doing so is technically wrong.
		 */
		case _SC_ASYNCHRONOUS_IO:
		case _SC_FSYNC:
		case _SC_MAPPED_FILES:
		case _SC_MEMLOCK:
		case _SC_MEMLOCK_RANGE:
		case _SC_MEMORY_PROTECTION:
		case _SC_MESSAGE_PASSING:
		case _SC_PRIORITY_SCHEDULING:
		case _SC_REALTIME_SIGNALS:
		case _SC_SEMAPHORES:
		case _SC_SHARED_MEMORY_OBJECTS:
		case _SC_SYNCHRONIZED_IO:
		case _SC_TIMERS:
			if (__xpg6 & _C99SUSv3_mode_ON)
				return (200112L);
			else
				return (1L);

		case _SC_PRIORITIZED_IO:
#ifdef _POSIX_PRIORITIZED_IO
			return (1L);
#else
			return (-1L);
#endif

		case _SC_AIO_LISTIO_MAX:
			return (_sysconfig(_CONFIG_AIO_LISTIO_MAX));

		case _SC_AIO_MAX:
			return (_sysconfig(_CONFIG_AIO_MAX));

		case _SC_AIO_PRIO_DELTA_MAX:
			return (_sysconfig(_CONFIG_AIO_PRIO_DELTA_MAX));

		case _SC_DELAYTIMER_MAX:
			return (_sysconfig(_CONFIG_DELAYTIMER_MAX));

		case _SC_MQ_OPEN_MAX:
			return (_sysconfig(_CONFIG_MQ_OPEN_MAX));

		case _SC_MQ_PRIO_MAX:
			return (_sysconfig(_CONFIG_MQ_PRIO_MAX));

		case _SC_RTSIG_MAX:
			return (_sysconfig(_CONFIG_RTSIG_MAX));

		case _SC_SEM_NSEMS_MAX:
			return (_sysconfig(_CONFIG_SEM_NSEMS_MAX));

		case _SC_SEM_VALUE_MAX:
			return (_sysconfig(_CONFIG_SEM_VALUE_MAX));

		case _SC_SIGQUEUE_MAX:
			return (_sysconfig(_CONFIG_SIGQUEUE_MAX));

		case _SC_SIGRT_MAX:
			return (_sysconfig(_CONFIG_SIGRT_MAX));

		case _SC_SIGRT_MIN:
			return (_sysconfig(_CONFIG_SIGRT_MIN));

		case _SC_TIMER_MAX:
			return (_sysconfig(_CONFIG_TIMER_MAX));

		case _SC_PHYS_PAGES:
			return (_sysconfig(_CONFIG_PHYS_PAGES));

		case _SC_AVPHYS_PAGES:
			return (_sysconfig(_CONFIG_AVPHYS_PAGES));

		/* XPG4/POSIX.1-1990/POSIX.2-1992 names */
		case _SC_2_C_BIND:
			if (__xpg6 & _C99SUSv3_XPG6_sysconf_version)
				return (200112L);
			else
				return (1L);

		case _SC_2_CHAR_TERM:
			return ((long)_POSIX2_CHAR_TERM);

		case _SC_2_C_DEV:
			if (__xpg6 & _C99SUSv3_XPG6_sysconf_version)
				return (200112L);
			else
				return (1L);

		case _SC_2_C_VERSION:
			if (__xpg6 & _C99SUSv3_XPG6_sysconf_version)
				return (200112L);
			else
				return (199209L);

		case _SC_2_FORT_DEV:
			return (-1L);

		case _SC_2_FORT_RUN:
			if (__xpg6 & _C99SUSv3_XPG6_sysconf_version)
				return (200112L);
			else
				return (1L);

		case _SC_2_LOCALEDEF:
			if (__xpg6 & _C99SUSv3_XPG6_sysconf_version)
				return (200112L);
			else
				return (1L);

		case _SC_2_SW_DEV:
			if (__xpg6 & _C99SUSv3_XPG6_sysconf_version)
				return (200112L);
			else
				return (1L);

		case _SC_2_UPE:
			if (__xpg6 & _C99SUSv3_XPG6_sysconf_version)
				return (200112L);
			else
				return (1L);

		case _SC_2_VERSION:
			if (__xpg6 & _C99SUSv3_XPG6_sysconf_version)
				return (200112L);
			else
				return (199209L);

		case _SC_BC_BASE_MAX:
			return ((long)BC_BASE_MAX);

		case _SC_BC_DIM_MAX:
			return ((long)BC_DIM_MAX);

		case _SC_BC_SCALE_MAX:
			return ((long)BC_SCALE_MAX);

		case _SC_BC_STRING_MAX:
			return ((long)BC_STRING_MAX);

		case _SC_COLL_WEIGHTS_MAX:
			return ((long)COLL_WEIGHTS_MAX);

		case _SC_EXPR_NEST_MAX:
			return ((long)EXPR_NEST_MAX);

		case _SC_LINE_MAX:
			return ((long)LINE_MAX);

		case _SC_RE_DUP_MAX:
			return ((long)RE_DUP_MAX);

		case _SC_XOPEN_CRYPT:
			return (1L);

		case _SC_XOPEN_ENH_I18N:
			return ((long)_XOPEN_ENH_I18N);

		case _SC_XOPEN_SHM:
			return ((long)_XOPEN_SHM);

		/* XPG4v2 (SUS) names */
		case _SC_XOPEN_UNIX:
			return (1L);

		case _SC_XOPEN_LEGACY:
			return (1L);

		case _SC_ATEXIT_MAX:
			return (-1L);

		case _SC_IOV_MAX:
			return ((long)IOV_MAX);

		case _SC_T_IOV_MAX:
			return ((long)T_IOV_MAX);

		/* XPG5 (SUSv2) names */
		case _SC_XOPEN_REALTIME:
			return (1L);

		case _SC_XOPEN_REALTIME_THREADS:
#if defined(_POSIX_THREAD_PRIORITY_SCHEDULING) && \
	defined(_POSIX_THREAD_PRIO_INHERIT) && \
	defined(_POSIX_THREAD_PRIO_PROTECT)
			return (1L);
#else
			return (-1L);
#endif

		case _SC_XBS5_ILP32_OFF32:
			return (1L);

		case _SC_XBS5_ILP32_OFFBIG:
			return (1L);

		case _SC_XBS5_LP64_OFF64:
			return (1L);

		case _SC_XBS5_LPBIG_OFFBIG:
			return (1L);

		/* POSIX.1c names */
		case _SC_THREAD_DESTRUCTOR_ITERATIONS:
			return (-1L);

		case _SC_GETGR_R_SIZE_MAX:
			return ((long)_nss_get_bufsizes(_SC_GETGR_R_SIZE_MAX));

		case _SC_GETPW_R_SIZE_MAX:
			return ((long)NSS_BUFLEN_PASSWD);

		case _SC_LOGIN_NAME_MAX:
			return ((long)(LOGIN_NAME_MAX));

		case _SC_THREAD_KEYS_MAX:
			return (-1L);

		case _SC_THREAD_STACK_MIN:
			return ((long)thr_min_stack());

		case _SC_THREAD_THREADS_MAX:
			return (-1L);

		case _SC_TTY_NAME_MAX:
			return ((long)TTYNAME_MAX);

		case _SC_BARRIERS:
			return ((long)_POSIX_BARRIERS);

		case _SC_CLOCK_SELECTION:
			return ((long)_POSIX_CLOCK_SELECTION);

		case _SC_MONOTONIC_CLOCK:
			return ((long)_POSIX_MONOTONIC_CLOCK);

		case _SC_SPAWN:
			return ((long)_POSIX_SPAWN);

		case _SC_SPIN_LOCKS:
			return ((long)_POSIX_SPIN_LOCKS);

		case _SC_THREADS:
		case _SC_THREAD_ATTR_STACKADDR:
		case _SC_THREAD_ATTR_STACKSIZE:
		case _SC_THREAD_PRIORITY_SCHEDULING:
		case _SC_THREAD_PRIO_INHERIT:
		case _SC_THREAD_PRIO_PROTECT:
		case _SC_THREAD_PROCESS_SHARED:
		case _SC_THREAD_SAFE_FUNCTIONS:
			if (__xpg6 & _C99SUSv3_mode_ON)
				return (200112L);
			else
				return (1L);

		case _SC_TIMEOUTS:
			return ((long)_POSIX_TIMEOUTS);

		/* 1216676 - cache info */
		case _SC_COHER_BLKSZ:
			return (_sysconfig(_CONFIG_COHERENCY));

		case _SC_SPLIT_CACHE:
			return (_sysconfig(_CONFIG_SPLIT_CACHE));

		case _SC_ICACHE_SZ:
			return (_sysconfig(_CONFIG_ICACHESZ));

		case _SC_DCACHE_SZ:
			return (_sysconfig(_CONFIG_DCACHESZ));

		case _SC_ICACHE_LINESZ:
			return (_sysconfig(_CONFIG_ICACHELINESZ));

		case _SC_DCACHE_LINESZ:
			return (_sysconfig(_CONFIG_DCACHELINESZ));

		case _SC_ICACHE_BLKSZ:
			return (_sysconfig(_CONFIG_ICACHEBLKSZ));

		case _SC_DCACHE_BLKSZ:
			return (_sysconfig(_CONFIG_DCACHEBLKSZ));

		case _SC_DCACHE_TBLKSZ:
			return (_sysconfig(_CONFIG_DCACHETBLKSZ));

		case _SC_ICACHE_ASSOC:
			return (_sysconfig(_CONFIG_ICACHE_ASSOC));

		case _SC_DCACHE_ASSOC:
			return (_sysconfig(_CONFIG_DCACHE_ASSOC));

		case _SC_MAXPID:
			if (_maxpid <= 0)
				_maxpid = _sysconfig(_CONFIG_MAXPID);
			return (_maxpid);

		case _SC_CPUID_MAX:
			return (_sysconfig(_CONFIG_CPUID_MAX));

		case _SC_EPHID_MAX:
			return (_sysconfig(_CONFIG_EPHID_MAX));

		/* UNIX 03 names - XPG6/SUSv3/POSIX.1-2001 */

		case _SC_REGEXP:
			return ((long)_POSIX_REGEXP);

		case _SC_SHELL:
			return ((long)_POSIX_SHELL);

		case _SC_ADVISORY_INFO:
			return ((long)_POSIX_ADVISORY_INFO);

		case _SC_HOST_NAME_MAX:
			return ((long)_POSIX_HOST_NAME_MAX);

		case _SC_READER_WRITER_LOCKS:
			return ((long)_POSIX_READER_WRITER_LOCKS);

		case _SC_IPV6:
			return ((long)_POSIX_IPV6);

		case _SC_RAW_SOCKETS:
			return ((long)_POSIX_RAW_SOCKETS);

		case _SC_XOPEN_STREAMS:
			return ((long)_XOPEN_STREAMS);

		case _SC_SYMLOOP_MAX:
			return (_sysconfig(_CONFIG_SYMLOOP_MAX));

		case _SC_V6_ILP32_OFF32:
			return (1L);

		case _SC_V6_ILP32_OFFBIG:
			return (1L);

		case _SC_V6_LP64_OFF64:
			return (1L);

		case _SC_V6_LPBIG_OFFBIG:
			return (1L);

		/* Unsupported UNIX 03 options */
		case _SC_2_PBS:
		case _SC_2_PBS_ACCOUNTING:
		case _SC_2_PBS_CHECKPOINT:
		case _SC_2_PBS_LOCATE:
		case _SC_2_PBS_MESSAGE:
		case _SC_2_PBS_TRACK:
		case _SC_CPUTIME:
		case _SC_SPORADIC_SERVER:
		case _SC_SS_REPL_MAX:
		case _SC_THREAD_CPUTIME:
		case _SC_THREAD_SPORADIC_SERVER:
		case _SC_TRACE:
		case _SC_TRACE_EVENT_FILTER:
		case _SC_TRACE_EVENT_NAME_MAX:
		case _SC_TRACE_INHERIT:
		case _SC_TRACE_LOG:
		case _SC_TRACE_NAME_MAX:
		case _SC_TRACE_SYS_MAX:
		case _SC_TRACE_USER_EVENT_MAX:
		case _SC_TYPED_MEMORY_OBJECTS:
			return (-1L);
	}
}

/*
 * UNIX 98 version of sysconf needed in order to set _XOPEN_VERSION to 500.
 */

long
__sysconf_xpg5(int name)
{
	switch (name) {
		default:
			return (sysconf(name));
		case _SC_XOPEN_VERSION:
			return (500L);
		case _SC_PASS_MAX:
			return ((long)_PASS_MAX_XPG);
	}
}
