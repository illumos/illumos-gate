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
 * Copyright (c) 2017 Peter Tribble.
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

#ifndef __INSTALL_H
#define	__INSTALL_H


#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <limits.h>
#include <pkgstrct.h>

/* Settings for procedure scripts */
#define	PROC_USER	"root"
#define	PROC_GRP	"other"
#define	PROC_STDIN	"/dev/null"
#define	PROC_XSTDIN	"/dev/tty"
#define	PROC_STDOUT	"/dev/tty"

/* Settings for class action scripts */
#define	CAS_USER	"root"
#define	CAS_GRP		"other"
#define	CAS_STDIN	"/dev/null"
#define	CAS_STDOUT	"/dev/tty"

/* Settings for non-privileged scripts */
#define	CHK_USER	"install"	/* default user i.d. to use */
#define	CHK_USER_ALT	"noaccess"	/* alternate non-priv user */
#define	CHK_USER_ROOT	"root"		/* root user */
#define	CHK_USER_NON	"root"		/* user for non-compliant pkg's */
#define	CHK_GRP		"other"
#define	CHK_STDIN	"/dev/null"
#define	CHK_STDOUT	"/dev/tty"

/* Settings for admin "rscriptalt" option */
#define	RSCRIPTALT		rscriptalt
#define	RSCRIPTALT_KEYWORD	"rscriptalt"
#define	RSCRIPTALT_ROOT		"root"
#define	RSCRIPTALT_NOACCESS	"noaccess"

#define	OAMBASE	"/usr/sadm/sysadm"
#define	MAILCMD	"/usr/bin/mail"
#define	DATSTRM	"datastream"
#define	SHELL	"/sbin/sh"
#define	PKGINFO	"pkginfo"
#define	PKGMAP	"pkgmap"
#define	LIVE_CONT	"__live_cont__"
#define	RELOC "reloc"
#define	ROOT "root"

/* Additional cfent/cfextra codes. */
#define	BADFSYS	(short)(-1) /* an fsys is needed */
#define	BADINDEX    (-1)    /* pkg class idx not yet set */

/* This holds admin file data. */
struct admin {
	char	*mail;
	char	*instance;
	char	*partial;
	char	*runlevel;
	char	*idepend;
	char	*rdepend;
	char	*space;
	char	*setuid;
	char	*conflict;
	char	*action;
	char	*basedir;
	char	*rscriptalt;
};

/*
 * This table details the status of all filesystems available to the target
 * host.
 */
struct fstable {
	char	*name;	/* name of filesystem, (mount point) */
	int	namlen;	/* The length of the name (mountpoint) */
	fsblkcnt_t bsize;	/* fundamental file system block size */
	fsblkcnt_t frsize;	/* file system fragment size */
	fsblkcnt_t bfree;	/* total # of free blocks */
	fsblkcnt_t bused;	/* total # of used blocks */
	fsblkcnt_t ffree;	/* total # of free file nodes */
	fsblkcnt_t fused;	/* total # of used file nodes */
	char	*fstype;	/* type of filesystem - nfs, lo, ... */
	char	*remote_name;	/* client's mounted filesystem */
	unsigned	writeable:1;	/* access permission */
	unsigned	write_tested:1;	/* access permission fully tested */
	unsigned	remote:1;	/* on a remote filesystem */
	unsigned	mounted:1;	/* actually mounted right now */
	unsigned	srvr_map:1;	/* use server_map() */
	unsigned	cl_mounted:1;	/* mounted in client space */
	unsigned	mnt_failed:1;	/* attempt to loopback mount failed */
	unsigned	served:1;	/* filesystem comes from a server */
};

#define	ADM(x, y)	((adm.x != NULL) && (y != NULL) && \
			    strcmp(adm.x, y) == 0)
#define	ADMSET(x)	(adm.x != NULL)
#define	PARAMETRIC(x) (x[0] == '$')
#define	RELATIVE(x)	(x[0] != '/')

#if defined(lint) && !defined(gettext)
#define	gettext(x)	x
#endif	/* defined(lint) && !defined(gettext) */

#ifdef __cplusplus
}
#endif

#endif	/* __INSTALL_H */
