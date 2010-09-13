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

#ifndef	_PKGSTRCT_H
#define	_PKGSTRCT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.9	*/

#include <time.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	CLSSIZ	64
#define	PKGSIZ	64
#define	ATRSIZ	64

#define	BADFTYPE	'?'
#define	BADMODE		(mode_t)ULONG_MAX
#define	BADOWNER	"?"
#define	BADGROUP	"?"
#define	BADMAJOR	(major_t)ULONG_MAX
#define	BADMINOR	(minor_t)ULONG_MAX
#define	BADCLASS	"none"
#define	BADINPUT	1 /* not EOF */
#define	BADCONT		(-1L)

extern char	*errstr;

struct ainfo {
	char	*local;
	mode_t	mode;
	char	owner[ATRSIZ+1];
	char	group[ATRSIZ+1];
	major_t	major;
	minor_t	minor;
};

struct cinfo {
	long		cksum;
	fsblkcnt_t	size;
	time_t		modtime;
};

struct pinfo {
	char	status;
	char	pkg[PKGSIZ+1];
	char	editflag;
	char	aclass[ATRSIZ+1];
	struct pinfo
		*next;
};

struct cfent {
	short	volno;
	char	ftype;
	char	pkg_class[CLSSIZ+1];
	int	pkg_class_idx;
	char	*path;
	struct ainfo ainfo;
	struct cinfo cinfo;
	short	npkgs;
	struct pinfo
		*pinfo;
};

/* averify() & cverify() error codes */
#define	VE_EXIST	0x0001
#define	VE_FTYPE	0x0002
#define	VE_ATTR		0x0004
#define	VE_CONT		0x0008
#define	VE_FAIL		0x0010
#define	VE_TIME		0x0020

#ifdef	__cplusplus
}
#endif

#endif	/* _PKGSTRCT_H */
