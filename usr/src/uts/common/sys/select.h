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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 *
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef _SYS_SELECT_H
#define	_SYS_SELECT_H

#include <sys/feature_tests.h>

#if !defined(_KERNEL) && !defined(_FAKE_KERNEL)
#if !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || defined(__EXTENSIONS__)
#include <sys/time_impl.h>
#endif
#include <sys/time.h>
#endif /* !_KERNEL */

#ifdef	__cplusplus
extern "C" {
#endif


#if !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || defined(__EXTENSIONS__)
/*
 * The sigset_t type is defined in <sys/signal.h> and duplicated
 * in <sys/ucontext.h> as a result of XPG4v2 requirements. XPG6
 * now allows the visibility of signal.h in this header, however
 * an order of inclusion problem occurs as a result of inclusion
 * of <sys/select.h> in <signal.h> under certain conditions.
 * Rather than include <sys/signal.h> here, we've duplicated
 * the sigset_t type instead. This type is required for the XPG6
 * introduced pselect() function also declared in this header.
 */
#ifndef	_SIGSET_T
#define	_SIGSET_T
typedef struct {		/* signal set type */
	unsigned int	__sigbits[4];
} sigset_t;
#endif  /* _SIGSET_T */

#endif /* #if !defined(__XOPEN_OR_POSIX) || defined(_XPG6) ... */

/*
 * Select uses bit masks of file descriptors in longs.
 * These macros manipulate such bit fields.
 * FD_SETSIZE may be defined by the user, but the default here
 * should be >= NOFILE (param.h).
 */
#ifndef	FD_SETSIZE
#ifdef _LP64
#define	FD_SETSIZE	65536
#else
#define	FD_SETSIZE	1024
#endif	/* _LP64 */
#elif FD_SETSIZE > 1024 && !defined(_LP64)
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname	select	select_large_fdset
#if !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || defined(__EXTENSIONS__)
#pragma	redefine_extname	pselect	pselect_large_fdset
#endif
#else	/* __PRAGMA_REDEFINE_EXTNAME */
#define	select	select_large_fdset
#if !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || defined(__EXTENSIONS__)
#define	pselect	pselect_large_fdset
#endif
#endif	/* __PRAGMA_REDEFINE_EXTNAME */
#endif	/* FD_SETSIZE */

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
typedef	long	fd_mask;
#endif
typedef	long	fds_mask;

/*
 *  The value of _NBBY needs to be consistant with the value
 *  of NBBY in <sys/param.h>.
 */
#define	_NBBY 8
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#ifndef NBBY		/* number of bits per byte */
#define	NBBY _NBBY
#endif
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	NFDBITS		(sizeof (fd_mask) * NBBY)	/* bits per mask */
#endif
#define	FD_NFDBITS	(sizeof (fds_mask) * _NBBY)	/* bits per mask */

#define	__howmany(__x, __y)	(((__x)+((__y)-1))/(__y))
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#ifndef	howmany
#define	howmany(x, y)	(((x)+((y)-1))/(y))
#endif
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
typedef	struct fd_set {
#else
typedef	struct __fd_set {
#endif
	long	fds_bits[__howmany(FD_SETSIZE, FD_NFDBITS)];
} fd_set;

#define	FD_SET(__n, __p)	((__p)->fds_bits[(__n)/FD_NFDBITS] |= \
				    (1ul << ((__n) % FD_NFDBITS)))

#define	FD_CLR(__n, __p)	((__p)->fds_bits[(__n)/FD_NFDBITS] &= \
				    ~(1ul << ((__n) % FD_NFDBITS)))

#define	FD_ISSET(__n, __p)	(((__p)->fds_bits[(__n)/FD_NFDBITS] & \
				    (1ul << ((__n) % FD_NFDBITS))) != 0l)

#if defined(_KERNEL) || defined(_FAKE_KERNEL)
#define	FD_ZERO(p)	bzero((p), sizeof (*(p)))
#else
#define	FD_ZERO(__p)    (void) memset((__p), 0, sizeof (*(__p)))
#endif /* _KERNEL */

#if !defined(_KERNEL) && !defined(_FAKE_KERNEL)
extern int select(int, fd_set *_RESTRICT_KYWD, fd_set *_RESTRICT_KYWD,
	fd_set *_RESTRICT_KYWD, struct timeval *_RESTRICT_KYWD);

#if !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || defined(__EXTENSIONS__)
extern int pselect(int, fd_set *_RESTRICT_KYWD, fd_set *_RESTRICT_KYWD,
	fd_set *_RESTRICT_KYWD, const struct timespec *_RESTRICT_KYWD,
	const sigset_t *_RESTRICT_KYWD);
#endif

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SELECT_H */
