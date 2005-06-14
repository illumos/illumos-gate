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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef	_USERDEFS_H
#define	_USERDEFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.7.1.1 */

#include <project.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The definitions in this file are local to the OA&M subsystem.  General
 * use is not encouraged.
 */

/* User/group default values */
#define	DEFGID		99	/* max reserved group id */
#define	DEFRID		99
#define	DEFPROJ		3
#define	DEFPROJNAME	"default"
#define	DEFGROUP	1
#define	DEFGNAME	"other"
#define	DEFPARENT	"/home"
#define	DEFSKL		"/etc/skel"
#define	DEFSHL		"/bin/sh"
#define	DEFROLESHL	"/bin/pfsh"
#define	DEFINACT	0
#define	DEFEXPIRE	""
#define	DEFAUTH		""
#define	DEFPROF		""
#define	DEFROLEPROF	"All"
#define	DEFROLE		""
#define	DEFLIMPRIV	""
#define	DEFDFLTPRIV	""
#define	DEFLOCK_AFTER_RETRIES	""

/* Defaults file keywords */
#define	RIDSTR		"defrid="
#define	GIDSTR		"defgroup="
#define	GNAMSTR		"defgname="
#define	PARSTR		"defparent="
#define	SKLSTR		"defskel="
#define	SHELLSTR	"defshell="
#define	INACTSTR	"definact="
#define	EXPIRESTR	"defexpire="
#define	AUTHSTR		"defauthorization="
#define	PROFSTR		"defprofile="
#define	ROLESTR		"defrole="
#define	PROJSTR		"defproj="
#define	PROJNMSTR	"defprojname="
#define	LIMPRSTR	"deflimitpriv="
#define	DFLTPRSTR	"defdefaultpriv="
#define	FHEADER		"#	Default values for useradd.  Changed "
#define	FHEADER_ROLE	"#	Default values for roleadd.  Changed "
#define	LOCK_AFTER_RETRIESSTR	"deflock_after_retries="

/* Defaults file */
#define	DEFFILE		"/usr/sadm/defadduser"
#define	DEFROLEFILE	"/usr/sadm/defaddrole"
#define	GROUP		"/etc/group"

/* various limits */
#define	MAXGLEN		9	/* max length of group name */
#define	MAXDLEN		80	/* max length of a date string */

/* defaults structure */
struct userdefs {
	int defrid;		/* highest reserved uid */
	int defgroup;		/* default group id */
	char *defgname;		/* default group name */
	char *defparent;	/* default base directory for new logins */
	char *defskel;		/* default skel directory */
	char *defshell;		/* default shell */
	int definact;		/* default inactive */
	char *defexpire;		/* default expire date */
	char *defauth;		/* default authorization */
	char *defprof;		/* default profile */
	char *defrole;		/* default role */
	projid_t defproj;	/* default project id */
	char *defprojname;	/* default project name */
	char *deflimpriv;	/* default limitpriv */
	char *defdfltpriv;	/* default defaultpriv */
	char *deflock_after_retries;	/* default lock_after_retries */

};

/* exit() values for user/group commands */

/* Everything succeeded */
#define	EX_SUCCESS	0

/* No permission */
#define	EX_NO_PERM	1

/* Command syntax error */
#define	EX_SYNTAX	2

/* Invalid argument given */
#define	EX_BADARG	3

/* A gid or uid already exists */
#define	EX_ID_EXISTS	4

/* PASSWD and SHADOW are inconsistent with each other */
#define	EX_INCONSISTENT	5

/* A group or user name  doesn't exist */
#define	EX_NAME_NOT_EXIST	6

/* GROUP, PASSWD, or SHADOW file missing */
#define	EX_MISSING	7

/* GROUP, PASSWD, or SHAWOW file is busy */
#define	EX_BUSY	8

/* A group or user name already exists */
#define	EX_NAME_EXISTS	9

/* Unable to update GROUP, PASSWD, or SHADOW file */
#define	EX_UPDATE	10

/* Not enough space */
#define	EX_NOSPACE	11

/* Unable to create/remove/move home directory */
#define	EX_HOMEDIR	12

/* new login already in use */
#define	EX_NL_USED	13

/* Unexpected failure */
#define	EX_FAILURE	14

/* A user name is in a non-local name service */
#define	EX_NOT_LOCAL	15

#ifdef	__cplusplus
}
#endif

#endif	/* _USERDEFS_H */
