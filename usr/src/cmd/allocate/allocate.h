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
 * Copyright 1992-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_ALLOCATE_H
#define	_ALLOCATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* Option Flags */
#define	SILENT		0001	/* -s */
#define	USERID		0002	/* -U */
#define	LIST		0004	/* -l */
#define	FREE		0010	/* -n */
#define	CURRENT 	0020	/* -u */
#define	FORCE		0040	/* -F */
#define	FORCE_ALL 	0100	/* -I */
#define	TYPE		0200	/* -g */

#define	ALLOC_OPTS	(SILENT | USERID | FORCE | TYPE)
#define	DEALLOC_OPTS	(SILENT | FORCE | FORCE_ALL)
#define	LIST_OPTS	(SILENT | USERID | LIST | FREE | CURRENT)

/* Misc. */

#define	ALL	-1

/* Error returns start at 4 */
#define	SYSERROR	4
#define	DACLCK		5
#define	DACACC		6
#define	DEVLST		7
#define	NALLOCU		8
#define	NOTAUTH		9
#define	CNTFRC		10
#define	CNTDEXEC	11
#define	NO_DEVICE	12
#define	DSPMISS		13
#define	ALLOCERR	14
#define	IMPORT_ERR	15
#define	NODAENT		16
#define	NODMAPENT	17
#define	SETACL_PERR	18
#define	CHOWN_PERR	19
#define	ALLOC		20
#define	ALLOC_OTHER	21
#define	NALLOC		22
#define	AUTHERR		23
#define	CLEAN_ERR	24
#define	DEVNAME_ERR	25
#define	DEVNAME_TOOLONG	26

/* Tunable Parameters */
#define	DEV_DIR		"/dev"
#define	DAC_DIR		"/etc/security/dev"
#define	SECLIB		"/etc/security/lib"
#define	ALLOC_MODE	0600
#define	DEALLOC_MODE    0000
#define	ALLOC_ERR_MODE  0100
#define	ALLOC_UID	(uid_t)0	/* root */
#define	ALLOC_GID	(gid_t)1	/* other */

/* Functions */
extern int allocate(int optflg, uid_t uid, char *device);
extern int deallocate(int optflg, uid_t uid, char *device);
extern int list_devices(int optflg, uid_t uid, char *device);

#ifdef	__cplusplus
}
#endif

#endif	/* _ALLOCATE_H */
