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
/*	  All Rights Reserved	*/


/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_UTSNAME_H
#define	_SYS_UTSNAME_H

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

extern int uname(struct utsname *);
extern int _uname(struct utsname *);

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
extern int nuname(struct utsname *);
#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */
extern int _nuname(struct utsname *);

/*
 * On i386 in SVID.2 uname() returns a utsname structure with 8 byte members,
 * and nuname() returns the real struct utsname.  In SVID.3 uname and nuname
 * are equivalent.  Anyone who includes this header gets the SVID.3 behaviour.
 * The SVID.2 behaviour exists solely for compatibility, and is what is
 * implemented by the libc uname/_uname entrypoints.
 */
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname	uname	_nuname
#pragma redefine_extname	_uname	_nuname
#else
#define	uname	_nuname
#define	_uname	_nuname
#endif

#else	/* defined(__i386) */

extern int uname(struct utsname *);

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
