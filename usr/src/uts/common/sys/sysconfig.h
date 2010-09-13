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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SYSCONFIG_H
#define	_SYS_SYSCONFIG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.5 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL
extern int	mach_sysconfig(int);
#endif	/* KERNEL */

/*
 * cmd values for _sysconfig system call.
 * WARNING: This is an undocumented system call,
 * therefore future compatibility can not
 * guaranteed.
 */

#define	 UNUSED			1
#define	_CONFIG_NGROUPS		2	/* # configured supplemental groups */
#define	_CONFIG_CHILD_MAX	3	/* max # of processes per uid session */
#define	_CONFIG_OPEN_FILES	4	/* max # of open files per process */
#define	_CONFIG_POSIX_VER	5	/* POSIX version */
#define	_CONFIG_PAGESIZE	6	/* system page size */
#define	_CONFIG_CLK_TCK		7	/* ticks per second */
#define	_CONFIG_XOPEN_VER	8

/*
 * NOTE: XOPEN VERSION. This is process dependent. The kernel will return
 * the default value, currently 3.
 */

#define	_CONFIG_PROF_TCK	10	/* profiling ticks per second */
#define	_CONFIG_NPROC_CONF	11	/* processors configured */
#define	_CONFIG_NPROC_ONLN	12	/* processors online */

/* posix dot4 names */
#define	_CONFIG_AIO_LISTIO_MAX	13	/* # of operation in a list I/O call */
#define	_CONFIG_AIO_MAX		14	/* # of outstanding async I/O op. */
#define	_CONFIG_AIO_PRIO_DELTA_MAX	15 /* amount I/O priority decrease */
#define	_CONFIG_DELAYTIMER_MAX	16	/* timer timer expiration overruns */
#define	_CONFIG_MQ_OPEN_MAX	17	/* # message queues open per process */
#define	_CONFIG_MQ_PRIO_MAX	18	/* # of message priorities supported */
#define	_CONFIG_RTSIG_MAX	19	/* # of realtime signal numbers */
#define	_CONFIG_SEM_NSEMS_MAX	20	/* No. of semaphore per process */
#define	_CONFIG_SEM_VALUE_MAX	21	/* max. value a semaphore may have */
#define	_CONFIG_SIGQUEUE_MAX	22	/* # of pending queued signal */
#define	_CONFIG_SIGRT_MIN	23	/* first highest-pri realtime signal */
#define	_CONFIG_SIGRT_MAX	24	/* last realtime signal */
#define	_CONFIG_TIMER_MAX	25	/* # of timers per process */

#define	_CONFIG_PHYS_PAGES	26	/* phys mem installed in pages */
#define	_CONFIG_AVPHYS_PAGES	27	/* available phys mem in pages */
#define	_CONFIG_COHERENCY	28	/* # bytes coherency */
#define	_CONFIG_SPLIT_CACHE	29	/* split i and d or not */
#define	_CONFIG_ICACHESZ	30	/* icache size in bytes */
#define	_CONFIG_DCACHESZ	31	/* dcache size in bytes */
#define	_CONFIG_ICACHELINESZ	32	/* linesize bytes */
#define	_CONFIG_DCACHELINESZ	33	/* linesize bytes */
#define	_CONFIG_ICACHEBLKSZ	34	/* block size bytes */
#define	_CONFIG_DCACHEBLKSZ	35	/* block size bytes */
#define	_CONFIG_DCACHETBLKSZ	36	/* block size bytes when touched */
#define	_CONFIG_ICACHE_ASSOC	37	/* associativity 1, 2, 3 whatever */
#define	_CONFIG_DCACHE_ASSOC	38	/* associativity 1, 2, 3 whatever */
#define	_CONFIG_MAXPID		42	/* highest PID available */
#define	_CONFIG_STACK_PROT	43	/* default stack protection */
#define	_CONFIG_NPROC_MAX	44	/* maximum # of processors possible */
#define	_CONFIG_CPUID_MAX	45	/* maximum CPU id */

/* UNIX 03 names */
#define	_CONFIG_SYMLOOP_MAX	46	/* maximum # of symlinks in pathname */

#define	_CONFIG_EPHID_MAX	47	/* maximum ephemeral uid */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SYSCONFIG_H */
