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
 * Copyright 1986 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#ifndef _sys_sem_h
#define	_sys_sem_h

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	IPC Semaphore Facility.
 */

/*
 *	Semaphore Operation Flags.
 */
#define	SEM_UNDO	010000	/* set up adjust on exit entry */

/*
 *	Semctl Command Definitions.
 */

#define	GETNCNT	3	/* get semncnt */
#define	GETPID	4	/* get sempid */
#define	GETVAL	5	/* get semval */
#define	GETALL	6	/* get all semval's */
#define	GETZCNT	7	/* get semzcnt */
#define	SETVAL	8	/* set semval */
#define	SETALL	9	/* set all semval's */

/*
 *	Structure Definitions.
 */

/*
 *	There is one semaphore id data structure for each set of semaphores
 *		in the system.
 */

struct semid_ds {
	struct ipc_perm	sem_perm;	/* operation permission struct */
	struct sem	*sem_base;	/* ptr to first semaphore in set */
	ushort		sem_nsems;	/* # of semaphores in set */
	time_t		sem_otime;	/* last semop time */
	time_t		sem_ctime;	/* last change time */
};

/*
 *	There is one semaphore structure for each semaphore in the system.
 */

struct sem {
	ushort	semval;		/* semaphore text map address */
	short	sempid;		/* pid of last operation */
	ushort	semncnt;	/* # awaiting semval > cval */
	ushort	semzcnt;	/* # awaiting semval = 0 */
};

/*
 *	User semaphore template for semop system calls.
 */

struct sembuf {
	short	sem_num;	/* semaphore # */
	short	sem_op;		/* semaphore operation */
	short	sem_flg;	/* operation flags */
};

/*
 *	'arg' argument template for semctl system calls.
 */
union semun {
	int		val;	/* value for SETVAL */
	struct semid_ds	*buf;	/* buffer for IPC_STAT & IPC_SET */
	ushort		*array;	/* array for GETALL & SETALL */
};

#endif /* !_sys_sem_h */
