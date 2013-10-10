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
 *
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _USERS_H
#define	_USERS_H


#include <pwd.h>
#include <grp.h>
#include <project.h>

#define	GROUP		"/etc/group"

/* max number of projects that can be specified when adding a user */
#define	NPROJECTS_MAX	1024

/* validation returns */
#define	NOTUNIQUE	0	/* not unique */
#define	RESERVED	1	/* reserved */
#define	UNIQUE		2	/* is unique */
#define	TOOBIG		3	/* number too big */
#define	INVALID		4
#define	LONGNAME	5	/* string too long */

/*
 * Note: constraints checking for warning (release 2.6),
 * and these may be enforced in the future releases.
 */
#define	WARN_NAME_TOO_LONG	0x1
#define	WARN_BAD_GROUP_NAME	0x2
#define	WARN_BAD_LOGNAME_CHAR	0x4
#define	WARN_BAD_LOGNAME_FIRST	0x8
#define	WARN_NO_LOWERCHAR	0x10
#define	WARN_BAD_PROJ_NAME	0x20
#define	WARN_LOGGED_IN		0x40

/* Exit codes from passmgmt */
#define	PEX_SUCCESS	0
#define	PEX_NO_PERM	1
#define	PEX_SYNTAX	2
#define	PEX_BADARG	3
#define	PEX_BADUID	4
#define	PEX_HOSED_FILES	5
#define	PEX_FAILED	6
#define	PEX_MISSING	7
#define	PEX_BUSY	8
#define	PEX_BADNAME	9

#define	REL_PATH(x)	(x && *x != '/')

/*
 * interfaces available from the library
 */
extern int valid_login(char *, struct passwd **, int *);
extern int valid_gname(char *, struct group **, int *);
extern int valid_group(char *, struct group **, int *);
extern int valid_project(char *, struct project *, void *buf, size_t, int *);
extern int valid_projname(char *, struct project *, void *buf, size_t, int *);
extern void warningmsg(int, char *);
extern void putgrent(struct group *, FILE *);

/* passmgmt */
#define	PASSMGMT	"/usr/lib/passmgmt";
#endif	/* _USERS_H */
