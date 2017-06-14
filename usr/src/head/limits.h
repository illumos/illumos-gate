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
 * Copyright 2017 RackTop Systems.
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/


#ifndef _LIMITS_H
#define	_LIMITS_H

#include <sys/feature_tests.h>
#include <sys/isa_defs.h>
#include <iso/limits_iso.h>

/*
 * Include fixed width type limits as proposed by the ISO/JTC1/SC22/WG14 C
 * committee's working draft for the revision of the current ISO C standard,
 * ISO/IEC 9899:1990 Programming language - C.  These are not currently
 * required by any standard but constitute a useful, general purpose set
 * of type definitions and limits which is namespace clean with respect to
 * all standards.
 */
#if defined(__EXTENSIONS__) || !defined(_STRICT_STDC) || \
	defined(__XOPEN_OR_POSIX)
#include <sys/int_limits.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(__EXTENSIONS__) || !defined(_STRICT_STDC) || \
	defined(__XOPEN_OR_POSIX)

#define	SSIZE_MAX	LONG_MAX	/* max value of an "ssize_t" */

/*
 * ARG_MAX is calculated as follows:
 * NCARGS - space for other stuff on initial stack
 * like aux vectors, saved registers, etc..
 */
#define	_ARG_MAX32	1048320	/* max length of args to exec 32-bit program */
#define	_ARG_MAX64	2096640	/* max length of args to exec 64-bit program */
#ifdef	_LP64
#define	ARG_MAX		_ARG_MAX64	/* max length of arguments to exec */
#else	/* _LP64 */
#define	ARG_MAX		_ARG_MAX32	/* max length of arguments to exec */
#endif	/* _LP64 */

#ifndef MAX_CANON
#define	MAX_CANON	256	/* max bytes in line for canonical processing */
#endif

#ifndef MAX_INPUT
#define	MAX_INPUT	512	/* max size of a char input buffer */
#endif

#define	NGROUPS_MAX	16	/* max number of groups for a user */

#ifndef PATH_MAX
#define	PATH_MAX	1024	/* max # of characters in a path name */
#endif

#define	SYMLINK_MAX	1024	/* max # of characters a symlink can contain */

#define	PIPE_BUF	5120	/* max # bytes atomic in write to a pipe */

#ifndef TMP_MAX
#define	TMP_MAX		17576	/* 26 * 26 * 26 */
#endif

/*
 * POSIX conformant definitions - An implementation may define
 * other symbols which reflect the actual implementation. Alternate
 * definitions may not be as restrictive as the POSIX definitions.
 */
#define	_POSIX_AIO_LISTIO_MAX	    2
#define	_POSIX_AIO_MAX		    1
#define	_POSIX_ARG_MAX		 4096
#ifdef _XPG6
#define	_POSIX_CHILD_MAX	   25
#else
#define	_POSIX_CHILD_MAX	    6	/* POSIX.1-1990 default */
#endif
#define	_POSIX_CLOCKRES_MIN	20000000
#define	_POSIX_DELAYTIMER_MAX	   32
#define	_POSIX_LINK_MAX		    8
#define	_POSIX_MAX_CANON	  255
#define	_POSIX_MAX_INPUT	  255
#define	_POSIX_MQ_OPEN_MAX	    8
#define	_POSIX_MQ_PRIO_MAX	   32
#define	_POSIX_NAME_MAX		   14
#ifdef _XPG6
#define	_POSIX_NGROUPS_MAX	    8
#define	_POSIX_OPEN_MAX		   20
#define	_POSIX_PATH_MAX		  256
#else					/* POSIX.1-1990 defaults */
#define	_POSIX_NGROUPS_MAX	    0
#define	_POSIX_OPEN_MAX		   16
#define	_POSIX_PATH_MAX		  255
#endif
#define	_POSIX_PIPE_BUF		  512
#define	_POSIX_RTSIG_MAX	    8
#define	_POSIX_SEM_NSEMS_MAX	  256
#define	_POSIX_SEM_VALUE_MAX	32767
#define	_POSIX_SIGQUEUE_MAX	   32
#define	_POSIX_SSIZE_MAX	32767
#define	_POSIX_STREAM_MAX	    8
#define	_POSIX_TIMER_MAX	   32
#ifdef _XPG6
#define	_POSIX_TZNAME_MAX	    6
#else
#define	_POSIX_TZNAME_MAX	    3	/* POSIX.1-1990 default */
#endif
/* POSIX.1c conformant */
#define	_POSIX_LOGIN_NAME_MAX			9
#define	_POSIX_THREAD_DESTRUCTOR_ITERATIONS	4
#define	_POSIX_THREAD_KEYS_MAX			128
#define	_POSIX_THREAD_THREADS_MAX		64
#define	_POSIX_TTY_NAME_MAX			9
/* UNIX 03 conformant */
#define	_POSIX_HOST_NAME_MAX			255
#define	_POSIX_RE_DUP_MAX			255
#define	_POSIX_SYMLINK_MAX			255
#define	_POSIX_SYMLOOP_MAX			8

/*
 * POSIX.2 and XPG4-XSH4 conformant definitions
 */

#define	_POSIX2_BC_BASE_MAX		  99
#define	_POSIX2_BC_DIM_MAX		2048
#define	_POSIX2_BC_SCALE_MAX		  99
#define	_POSIX2_BC_STRING_MAX		1000
#define	_POSIX2_COLL_WEIGHTS_MAX	   2
#define	_POSIX2_EXPR_NEST_MAX		  32
#define	_POSIX2_LINE_MAX		2048
#define	_POSIX2_RE_DUP_MAX		 255
/* UNIX 03 conformant */
#define	_POSIX2_CHARCLASS_NAME_MAX	  14

#define	BC_BASE_MAX		_POSIX2_BC_BASE_MAX
#define	BC_DIM_MAX		_POSIX2_BC_DIM_MAX
#define	BC_SCALE_MAX		_POSIX2_BC_SCALE_MAX
#define	BC_STRING_MAX		_POSIX2_BC_STRING_MAX
#define	COLL_WEIGHTS_MAX	10
#define	EXPR_NEST_MAX		_POSIX2_EXPR_NEST_MAX
#define	LINE_MAX		_POSIX2_LINE_MAX
#if !defined(_XPG6)
#define	RE_DUP_MAX		_POSIX2_RE_DUP_MAX
#else
#define	RE_DUP_MAX		_POSIX_RE_DUP_MAX
#endif /* !defined(_XPG6) */

#endif /* defined(__EXTENSIONS__) || !defined(_STRICT_STDC) ... */

#if defined(__EXTENSIONS__) || \
	(!defined(_STRICT_STDC) && !defined(_POSIX_C_SOURCE)) || \
	defined(_XOPEN_SOURCE)

/*
 * For dual definitions for PASS_MAX and sysconf.c
 */
#define	_PASS_MAX_XPG	8	/* old standards PASS_MAX */
#define	_PASS_MAX	256	/* modern Solaris PASS_MAX */

#if defined(_XPG3) && !defined(_XPG6)
#define	PASS_MAX	_PASS_MAX_XPG	/* max # of characters in a password */
#else	/* XPG6 or just Solaris */
#define	PASS_MAX	_PASS_MAX	/* max # of characters in a password */
#endif	/* defined(_XPG3) && !defined(_XPG6) */

#define	CHARCLASS_NAME_MAX	_POSIX2_CHARCLASS_NAME_MAX

#define	NL_ARGMAX	9	/* max value of "digit" in calls to the	*/
				/* NLS printf() and scanf() */
#define	NL_LANGMAX	14	/* max # of bytes in a LANG name */
#define	NL_MSGMAX	32767	/* max message number */
#define	NL_NMAX		1	/* max # bytes in N-to-1 mapping characters */
#define	NL_SETMAX	255	/* max set number */
#define	NL_TEXTMAX	2048	/* max set number */
#define	NZERO		20	/* default process priority */

#define	WORD_BIT	32	/* # of bits in a "word" or "int" */
#if defined(_LP64)
#define	LONG_BIT	64	/* # of bits in a "long" */
#else	/* _ILP32 */
#define	LONG_BIT	32	/* # of bits in a "long" */
#endif

/* Marked as LEGACY in SUSv2 and removed in UNIX 03 */
#ifndef _XPG6
#define	DBL_DIG		15	/* digits of precision of a "double" */
#define	DBL_MAX		1.7976931348623157081452E+308	/* max decimal value */
							/* of a double */
#define	FLT_DIG		6		/* digits of precision of a "float" */
#define	FLT_MAX		3.4028234663852885981170E+38F	/* max decimal value */
							/* of a "float" */
#endif

/* Marked as LEGACY in SUSv1 and removed in SUSv2 */
#ifndef _XPG5
#define	DBL_MIN		2.2250738585072013830903E-308	/* min decimal value */
							/* of a double */
#define	FLT_MIN		1.1754943508222875079688E-38F	/* min decimal value */
							/* of a float */
#endif

#endif	/* defined(__EXTENSIONS__) || (!defined(_STRICT_STDC) ... */

#define	_XOPEN_IOV_MAX	16	/* max # iovec/process with readv()/writev() */
#define	_XOPEN_NAME_MAX	255	/* max # bytes in filename excluding null */
#define	_XOPEN_PATH_MAX	1024	/* max # bytes in a pathname */

#define	IOV_MAX		_XOPEN_IOV_MAX

#if defined(__EXTENSIONS__) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX))

#define	FCHR_MAX	1048576		/* max size of a file in bytes */
#define	PID_MAX		999999		/* max value for a process ID */

/*
 * POSIX 1003.1a, section 2.9.5, table 2-5 contains [NAME_MAX] and the
 * related text states:
 *
 * A definition of one of the values from Table 2-5 shall be omitted from the
 * <limits.h> on specific implementations where the corresponding value is
 * equal to or greater than the stated minimum, but where the value can vary
 * depending on the file to which it is applied. The actual value supported for
 * a specific pathname shall be provided by the pathconf() (5.7.1) function.
 *
 * This is clear that any machine supporting multiple file system types
 * and/or a network should not include this define, regardless of protection
 * by the _POSIX_SOURCE and _POSIX_C_SOURCE flags. We chose to ignore that
 * and provide it anyway for compatibility with other platforms that don't
 * follow the spec as precisely as they should. Its usage is discouraged.
 */
#define	NAME_MAX	255

#define	CHILD_MAX	25	/* max # of processes per user id */
#ifndef OPEN_MAX
#define	OPEN_MAX	256	/* max # of files a process can have open */
#endif

#define	PIPE_MAX	5120	/* max # bytes written to a pipe in a write */

#define	STD_BLK		1024	/* # bytes in a physical I/O block */
#define	UID_MAX		2147483647	/* max value for a user or group ID */
#define	USI_MAX		4294967295	/* max decimal value of an "unsigned" */
#define	SYSPID_MAX	1	/* max pid of system processes */

#ifndef SYS_NMLN		/* also defined in sys/utsname.h */
#define	SYS_NMLN	257	/* 4.0 size of utsname elements */
#endif

#ifndef CLK_TCK

#if !defined(_CLOCK_T) || __cplusplus >= 199711L
#define	_CLOCK_T
typedef long	clock_t;
#endif	/* !_CLOCK_T */

extern long _sysconf(int);	/* System Private interface to sysconf() */
#define	CLK_TCK	((clock_t)_sysconf(3))	/* 3 is _SC_CLK_TCK */

#endif /* CLK_TCK */

#ifdef	__USE_LEGACY_LOGNAME__
#define	LOGNAME_MAX	8	/* max # of characters in a login name */
#else	/* __USE_LEGACY_LOGNAME__ */
#define	LOGNAME_MAX	32	/* max # of characters in a login name */
				/* Increased for illumos */
#endif	/* __USE_LEGACY_LOGNAME__ */
#define	LOGIN_NAME_MAX	(LOGNAME_MAX + 1)	/* max buffer size */
#define	LOGNAME_MAX_TRAD	8		/* traditional length */
#define	LOGIN_NAME_MAX_TRAD	(LOGNAME_MAX_TRAD + 1)	/* and size */

#define	TTYNAME_MAX	128	/* max # of characters in a tty name */

#endif	/* if defined(__EXTENSIONS__) || (!defined(_STRICT_STDC) ... */

#if	defined(__EXTENSIONS__) || (_POSIX_C_SOURCE >= 199506L)
#include <sys/unistd.h>

#if !defined(_SIZE_T) || __cplusplus >= 199711L
#define	_SIZE_T
#if defined(_LP64) || defined(_I32LPx)
typedef	unsigned long size_t;	/* size of something in bytes */
#else
typedef	unsigned int  size_t;	/* (historical version) */
#endif
#endif	/* _SIZE_T */

extern long _sysconf(int);	/* System Private interface to sysconf() */

#define	PTHREAD_STACK_MIN	((size_t)_sysconf(_SC_THREAD_STACK_MIN))
/* Added for UNIX98 conformance */
#define	PTHREAD_DESTRUCTOR_ITERATIONS	_POSIX_THREAD_DESTRUCTOR_ITERATIONS
#define	PTHREAD_KEYS_MAX		_POSIX_THREAD_KEYS_MAX
#define	PTHREAD_THREADS_MAX		_POSIX_THREAD_THREADS_MAX
#endif	/* defined(__EXTENSIONS__) || (_POSIX_C_SOURCE >= 199506L) */

#ifdef	__cplusplus
}
#endif

#endif	/* _LIMITS_H */
