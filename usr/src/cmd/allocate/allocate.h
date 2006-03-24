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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_ALLOCATE_H
#define	_ALLOCATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* Option Flags */
#define	LISTATTRS	0x00000001	/* -a */
#define	LISTDEFS	0x00000002	/* -d */
#define	TYPE		0x00000004	/* -g */
#define	LISTALL		0x00000008	/* -l */
#define	LISTFREE	0x00000010	/* -n */
#define	SILENT		0x00000020	/* -s */
#define	LISTALLOC 	0x00000040	/* -u */
#define	WINDOWING	0x00000080	/* -w */
#define	ZONENAME	0x00000100	/* -z */
#define	BOOT		0x00000200	/* -B */
#define	FORCE		0x00000400	/* -F */
#define	FORCE_ALL 	0x00000800	/* -I */
#define	USERID		0x00001000	/* -U for list_devices */
#define	USERNAME	0x00002000	/* -U for allocate */

/* Misc. */

#define	CLEAN_MOUNT		11	/* Also defined in disk_clean.sh */

#define	ALLOCUERR		1
#define	CHOWNERR		2
#define	CLEANERR		3
#define	CNTDEXECERR		4
#define	CNTFRCERR		5
#define	DACACCERR		6
#define	DAOFFERR		7
#define	DAUTHERR		8
#define	DEFATTRSERR		9
#define	DEVLKERR		10
#define	DEVLONGERR		11
#define	DEVNALLOCERR		12
#define	DEVNAMEERR		13
#define	DEVSTATEERR		14
#define	DEVZONEERR		15
#define	DSPMISSERR		16
#define	GLOBALERR		17
#define	LABELRNGERR		18
#define	LOGINDEVPERMERR		19
#define	NODAERR			20
#define	NODMAPERR		21
#define	PREALLOCERR		22
#define	SETACLERR		23
#define	UAUTHERR		24
#define	ZONEERR			25

#define	ALLOC_ERR_MODE  0100
#define	ALLOC_INVALID	0700

/* Functions */
extern int allocate(int optflg, uid_t uid, char *device, char *zonename);
extern int deallocate(int optflg, uid_t uid, char *device, char *zonename);
extern int list_devices(int optflg, uid_t uid, char *device, char *zonename);

#ifdef	__cplusplus
}
#endif

#endif	/* _ALLOCATE_H */
