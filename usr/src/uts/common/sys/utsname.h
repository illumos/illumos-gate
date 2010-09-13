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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_UTSNAME_H
#define	_SYS_UTSNAME_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/feature_tests.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	_SYS_NMLN	257	/* 4.0 size of utsname elements	*/
				/* Must be at least 257 to	*/
				/* support Internet hostnames.	*/

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
#ifndef	SYS_NMLN
#define	SYS_NMLN	_SYS_NMLN
#endif
#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

struct utsname {
	char	sysname[_SYS_NMLN];
	char	nodename[_SYS_NMLN];
	char	release[_SYS_NMLN];
	char	version[_SYS_NMLN];
	char	machine[_SYS_NMLN];
};

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
extern struct utsname utsname;
#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

#if !defined(_KERNEL)

#if defined(__i386) && !defined(__amd64)

#if defined(__STDC__)

#if !defined(__lint)
static int uname(struct utsname *);
static int _uname(struct utsname *);
#else
extern int uname(struct utsname *);
extern int _uname(struct utsname *);
#endif
#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
extern int nuname(struct utsname *);
#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */
extern int _nuname(struct utsname *);

#else	/* defined(__STDC__) */

#if !defined(__lint)
static int uname();
static int _uname();
#else
extern int uname();
extern int _uname();
#endif
#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
extern int nuname();
#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */
extern int _nuname();

#endif	/* defined(__STDC__) */


#if !defined(__lint)
static int
#if defined(__STDC__)
_uname(struct utsname *_buf)
#else
_uname(_buf)
struct utsname *_buf;
#endif
{
	return (_nuname(_buf));
}

static int
#if defined(__STDC__)
uname(struct utsname *_buf)
#else
uname(_buf)
struct utsname *_buf;
#endif
{
	return (_nuname(_buf));
}
#endif /* !defined(__lint) */

#else	/* defined(__i386) */

#if defined(__STDC__)
extern int uname(struct utsname *);
#else
extern int uname();
#endif	/* (__STDC__) */

#endif	/* defined(__i386) */

#else	/* !(_KERNEL) */
/*
 * Routine to retrieve the nodename as seen in the current process's zone.
 */
extern char *uts_nodename(void);
#endif	/* !(_KERNEL) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_UTSNAME_H */
