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
 */

#ifndef	_FB_CONFIG_H
#define	_FB_CONFIG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef  __cplusplus
extern "C" {
#endif

#define	HAVE_AIO 1
#define	HAVE_AIOCB64_T 1
#define	HAVE_AIOWAITN 1
#define	HAVE_AIO_H 1
#define	HAVE_CADDR_T 1
#define	HAVE_FORK 1
#define	HAVE_FORK1 1
#define	HAVE_HRTIME 1
#define	HAVE_LIBKSTAT 1
#define	HAVE_LWPS 1
#define	HAVE_MKSTEMP 1
#define	HAVE_OFF64_T 1
#define	HAVE_PROCFS 1
#define	HAVE_PROCSCOPE_PTHREADS 1
#define	HAVE_PTHREAD 1
#define	HAVE_PTHREAD_MUTEXATTR_SETPROTOCOL 1
#define	HAVE_ROBUST_MUTEX 1
#define	HAVE_SEMTIMEDOP 1
#define	HAVE_SETRLIMIT 1
#define	HAVE_SHM_SHARE_MMU 1
#define	HAVE_SIGSEND 1
#define	HAVE_STDINT_H 1
#define	HAVE_SYSV_SEM 1
#define	HAVE_SEM_RMID 1
#define	HAVE_SYS_INT_LIMITS_H 1
#define	HAVE_UINT64_MAX 1
#define	HAVE_UINT_T 1
#define	HAVE_BOOLEAN_T 1
#define	HAVE_U_LONGLONG_T 1
#define	HAVE_LIBTECLA 1
#define	HAVE_RAW_SUPPORT 1
#define	HAVE_FTRUNCATE64 1
#define	USE_PROCESS_MODEL 1

/* Define to 1 if you have the <libaio.h> header file. */
/* #undefHAVE_LIBAIO_H */

/* Checking if you have /proc/stat */
/* #undef HAVE_PROC_STAT */

/* Define to 1 if you have the <sys/async.h> header file. */
/* #undef HAVE_SYS_ASYNC_H */

/* Define if you want support for RDTSC. */
/* #undef USE_RDTSC */

#ifdef  __cplusplus
}
#endif

#endif	/* _FB_CONFIG_H */
