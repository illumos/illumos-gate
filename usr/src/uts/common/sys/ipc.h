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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 1996-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/



#ifndef _SYS_IPC_H
#define	_SYS_IPC_H

#include <sys/isa_defs.h>
#include <sys/feature_tests.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Common IPC access structure */

struct ipc_perm {
	uid_t		uid;	/* owner's user id */
	gid_t		gid;	/* owner's group id */
	uid_t		cuid;	/* creator's user id */
	gid_t		cgid;	/* creator's group id */
	mode_t		mode;	/* access modes */
	uint_t		seq;	/* slot usage sequence number */
	key_t		key;	/* key */
#if !defined(_LP64)
	int		pad[4]; /* reserve area */
#endif
};


/* Common IPC definitions */

/* Mode bits */
#define	IPC_ALLOC	0100000		/* entry currently allocated */
#define	IPC_CREAT	0001000		/* create entry if key doesn't exist */
#define	IPC_EXCL	0002000		/* fail if key exists */
#define	IPC_NOWAIT	0004000		/* error if request must wait */

/* Keys */
#define	IPC_PRIVATE	(key_t)0	/* private key */


/* Common IPC control commands */
#define	IPC_RMID	10	/* remove identifier */
#define	IPC_SET		11	/* set options */
#define	IPC_STAT	12	/* get options */


#if (!defined(_KERNEL) && !defined(_XOPEN_SOURCE)) || defined(_XPG4_2) || \
	defined(__EXTENSIONS__)
key_t ftok(const char *, int);
#endif /* (!defined(_KERNEL) && !defined(_XOPEN_SOURCE))... */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_IPC_H */
