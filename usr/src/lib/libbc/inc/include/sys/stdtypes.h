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
 * Copyright (c) 1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Suppose you have an ANSI C or POSIX thingy that needs a typedef
 * for thingy_t.  Put it here and include this file wherever you
 * define the thingy.  This is used so that we don't have size_t in
 * N (N > 1) different places and so that we don't have to have
 * types.h included all the time and so that we can include this in
 * the lint libs instead of termios.h which conflicts with ioctl.h.
 */

#ifndef	__SYS_STDTYPES_H
#define	__SYS_STDTYPES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

typedef	int		sigset_t;	/* signal mask - may change */

typedef	unsigned int	speed_t;	/* tty speeds */
typedef	unsigned long	tcflag_t;	/* tty line disc modes */
typedef	unsigned char	cc_t;		/* tty control char */
typedef	int		pid_t;		/* process id */

typedef	unsigned short	mode_t;		/* file mode bits */
typedef	short		nlink_t;	/* links to a file */

typedef	long		clock_t;	/* units=ticks (typically 60/sec) */
typedef	long		time_t;		/* value = secs since epoch */

typedef	int		size_t;		/* ??? */
typedef int		ptrdiff_t;	/* result of subtracting two pointers */

typedef	unsigned short	wchar_t;	/* big enough for biggest char set */

/*
 * POSIX Extensions
 */
typedef	unsigned char	uchar_t;
typedef	unsigned short	ushort_t;
typedef	unsigned int	uint_t;
typedef	unsigned long	ulong_t;

#ifdef __cplusplus
}
#endif

#endif	/* __SYS_STDTYPES_H */
