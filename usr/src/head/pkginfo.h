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


#ifndef	_PKGINFO_H
#define	_PKGINFO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.5.1.2 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	PI_INSTALLED 	0
#define	PI_PARTIAL	1
#define	PI_PRESVR4	2
#define	PI_UNKNOWN	3
#define	PI_SPOOLED	4

struct pkginfo {
	char	*pkginst;
	char	*name;
	char	*arch;
	char	*version;
	char	*vendor;
	char	*basedir;
	char	*catg;
	char	status;
};

extern char	*pkgdir;

#ifdef __STDC__
extern char	*pkgparam(char *, char *);
extern int	pkginfo(struct pkginfo *, char *, ...),
		pkgnmchk(char *, char *, int);
#else
extern char	*pkgparam();
extern int	pkginfo(),
		pkgnmchk();
#endif	/* __STDC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _PKGINFO_H */
