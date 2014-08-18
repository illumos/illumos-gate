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
 * Copyright 2014 Garrrett D'Amore <garrett@damore.org>
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef _SYS_RESOURCE_H
#define	_SYS_RESOURCE_H

#include <sys/feature_tests.h>

#include <sys/types.h>
#include <sys/time.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Process priority specifications
 */
#define	PRIO_PROCESS	0
#define	PRIO_PGRP	1
#define	PRIO_USER	2
#define	PRIO_GROUP	3
#define	PRIO_SESSION	4
#define	PRIO_LWP	5
#define	PRIO_TASK	6
#define	PRIO_PROJECT	7
#define	PRIO_ZONE	8
#define	PRIO_CONTRACT	9

/*
 * Resource limits
 */
#define	RLIMIT_CPU	0		/* cpu time in seconds */
#define	RLIMIT_FSIZE	1		/* maximum file size */
#define	RLIMIT_DATA	2		/* data size */
#define	RLIMIT_STACK	3		/* stack size */
#define	RLIMIT_CORE	4		/* core file size */
#define	RLIMIT_NOFILE	5		/* file descriptors */
#define	RLIMIT_VMEM	6		/* maximum mapped memory */
#define	RLIMIT_AS	RLIMIT_VMEM

#define	RLIM_NLIMITS	7		/* number of resource limits */

#if defined(_LP64)

typedef	unsigned long	rlim_t;

#define	RLIM_INFINITY	(-3l)
#define	RLIM_SAVED_MAX	(-2l)
#define	RLIM_SAVED_CUR	(-1l)

#else	/* _LP64 */

/*
 * The definitions of the following types and constants differ between the
 * regular and large file compilation environments.
 */
#if _FILE_OFFSET_BITS == 32

typedef unsigned long	rlim_t;

#define	RLIM_INFINITY	0x7fffffff
#define	RLIM_SAVED_MAX	0x7ffffffe
#define	RLIM_SAVED_CUR	0x7ffffffd

#else	/* _FILE_OFFSET_BITS == 32 */

typedef u_longlong_t	rlim_t;

#define	RLIM_INFINITY	((rlim_t)-3)
#define	RLIM_SAVED_MAX	((rlim_t)-2)
#define	RLIM_SAVED_CUR	((rlim_t)-1)

#endif	/* _FILE_OFFSET_BITS == 32 */

#endif	/* _LP64 */

#if defined(_SYSCALL32)

/* Kernel's view of user ILP32 rlimits */

typedef	uint32_t	rlim32_t;

#define	RLIM32_INFINITY		0x7fffffff
#define	RLIM32_SAVED_MAX	0x7ffffffe
#define	RLIM32_SAVED_CUR	0x7ffffffd

struct rlimit32 {
	rlim32_t	rlim_cur;	/* current limit */
	rlim32_t	rlim_max;	/* maximum value for rlim_cur */
};

#endif /* _SYSCALL32 */

struct rlimit {
	rlim_t	rlim_cur;		/* current limit */
	rlim_t	rlim_max;		/* maximum value for rlim_cur */
};

/* transitional large file interface versions */
#ifdef	_LARGEFILE64_SOURCE

typedef u_longlong_t	rlim64_t;

#define	RLIM64_INFINITY		((rlim64_t)-3)
#define	RLIM64_SAVED_MAX	((rlim64_t)-2)
#define	RLIM64_SAVED_CUR	((rlim64_t)-1)

struct rlimit64 {
	rlim64_t	rlim_cur;	/* current limit */
	rlim64_t	rlim_max;	/* maximum value for rlim_cur */
};

#endif

/*
 * Although the saved rlimits were initially introduced by the large file API,
 * they are now available for all resource limits on the 64-bit kernel and for
 * cpu time and file size limits on the 32-bit kernel.
 */
#if defined(_LP64)

#define	RLIM_SAVED(x)	(1)			/* save all resource limits */
#define	RLIM_NSAVED	RLIM_NLIMITS		/* size of u_saved_rlimits[] */

#else	/* _LP64 */

#define	RLIM_SAVED(x)	(x <= RLIMIT_FSIZE)	/* cpu time and file size */
#define	RLIM_NSAVED	(RLIMIT_FSIZE + 1)	/* size of u_saved_rlimits[] */

#endif	/* _LP64 */


struct	rusage {
	struct timeval ru_utime;	/* user time used */
	struct timeval ru_stime;	/* system time used */
	long	ru_maxrss;		/* <unimp> */
	long	ru_ixrss;		/* <unimp> */
	long	ru_idrss;		/* <unimp> */
	long	ru_isrss;		/* <unimp> */
	long	ru_minflt;		/* any page faults not requiring I/O */
	long	ru_majflt;		/* any page faults requiring I/O */
	long	ru_nswap;		/* swaps */
	long	ru_inblock;		/* block input operations */
	long	ru_oublock;		/* block output operations */
	long	ru_msgsnd;		/* streams messsages sent */
	long	ru_msgrcv;		/* streams messages received */
	long	ru_nsignals;		/* signals received */
	long	ru_nvcsw;		/* voluntary context switches */
	long	ru_nivcsw;		/* involuntary " */
};

#define	_RUSAGESYS_GETRUSAGE		0	/* rusage process */
#define	_RUSAGESYS_GETRUSAGE_CHLD	1	/* rusage child process */
#define	_RUSAGESYS_GETRUSAGE_LWP	2	/* rusage lwp */
#define	_RUSAGESYS_GETVMUSAGE		3	/* getvmusage */
#define	_RUSAGESYS_INVALMAP		4	/* vm_map_inval */

#if defined(_SYSCALL32)

struct	rusage32 {
	struct timeval32 ru_utime;	/* user time used */
	struct timeval32 ru_stime;	/* system time used */
	int	ru_maxrss;		/* <unimp> */
	int	ru_ixrss;		/* <unimp> */
	int	ru_idrss;		/* <unimp> */
	int	ru_isrss;		/* <unimp> */
	int	ru_minflt;		/* any page faults not requiring I/O */
	int	ru_majflt;		/* any page faults requiring I/O */
	int	ru_nswap;		/* swaps */
	int	ru_inblock;		/* block input operations */
	int	ru_oublock;		/* block output operations */
	int	ru_msgsnd;		/* streams messages sent */
	int	ru_msgrcv;		/* streams messages received */
	int	ru_nsignals;		/* signals received */
	int	ru_nvcsw;		/* voluntary context switches */
	int	ru_nivcsw;		/* involuntary " */
};

#endif	/* _SYSCALL32 */


#ifdef _KERNEL

#include <sys/model.h>

struct proc;

#else

#define	RUSAGE_SELF	0
#define	RUSAGE_LWP	1
#define	RUSAGE_CHILDREN	-1


#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
/*
 * large file compilation environment setup
 */
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname	setrlimit	setrlimit64
#pragma redefine_extname	getrlimit	getrlimit64
#else
#define	setrlimit		setrlimit64
#define	getrlimit		getrlimit64
#define	rlimit			rlimit64
#endif
#endif	/* !_LP64 && _FILE_OFFSET_BITS == 64 */

#if defined(_LP64) && defined(_LARGEFILE64_SOURCE)
/*
 * In the LP64 compilation environment, map large file interfaces
 * back to native versions where possible.
 */
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname	setrlimit64	setrlimit
#pragma	redefine_extname	getrlimit64	getrlimit
#else
#define	setrlimit64		setrlimit
#define	getrlimit64		getrlimit
#define	rlimit64		rlimit
#endif
#endif	/* _LP64 && _LARGEFILE64_SOURCE */

extern int setrlimit(int, const struct rlimit *);
extern int getrlimit(int, struct rlimit *);

/* transitional large file interfaces */
#if	defined(_LARGEFILE64_SOURCE) && !((_FILE_OFFSET_BITS == 64) && \
	    !defined(__PRAGMA_REDEFINE_EXTNAME))
extern int setrlimit64(int, const struct rlimit64 *);
extern int getrlimit64(int, struct rlimit64 *);
#endif	/* _LARGEFILE64_SOURCE... */

extern int getpriority(int, id_t);
extern int setpriority(int, id_t, int);
extern int getrusage(int, struct rusage *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RESOURCE_H */
