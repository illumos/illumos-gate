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
 * Copyright 1997-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


#ifndef _SYS_SEM_H
#define	_SYS_SEM_H

#include <sys/ipc.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * IPC Semaphore Facility.
 */

/*
 * Implementation Constants.
 */

/*
 * Permission Definitions.
 */

#define	SEM_A	0200	/* alter permission */
#define	SEM_R	0400	/* read permission */

/*
 * Semaphore Operation Flags.
 */

#define	SEM_UNDO	010000	/* set up adjust on exit entry */

/*
 * Semctl Command Definitions.
 */

#define	GETNCNT	3	/* get semncnt */
#define	GETPID	4	/* get sempid */
#define	GETVAL	5	/* get semval */
#define	GETALL	6	/* get all semval's */
#define	GETZCNT	7	/* get semzcnt */
#define	SETVAL	8	/* set semval */
#define	SETALL	9	/* set all semval's */

/*
 * Structure Definitions.
 */

struct semid_ds {
	struct ipc_perm sem_perm;	/* operation permission struct */
	struct sem	*sem_base;	/* ptr to first semaphore in set */
	ushort_t	sem_nsems;	/* # of semaphores in set */
#if defined(_LP64)
	time_t		sem_otime;	/* last semop time */
	time_t		sem_ctime;	/* last change time */
#else	/* _LP64 */
	time_t		sem_otime;	/* last semop time */
	int32_t		sem_pad1;	/* reserved for time_t expansion */
	time_t		sem_ctime;	/* last change time */
	int32_t		sem_pad2;	/* time_t expansion */
#endif	/* _LP64 */
	int		sem_binary;	/* flag indicating semaphore type */
	long		sem_pad3[3];	/* reserve area */
};

/*
 * User semaphore template for semop system calls.
 */
struct sembuf {
	ushort_t	sem_num;	/* semaphore # */
	short		sem_op;		/* semaphore operation */
	short		sem_flg;	/* operation flags */
};

#if !defined(_KERNEL)
int semctl(int, int, int, ...);
int semget(key_t, int, int);
int semids(int *, uint_t, uint_t *);
int semop(int, struct sembuf *, size_t);
#if defined(__EXTENSIONS__) || !defined(_XOPEN_SOURCE)
int semtimedop(int, struct sembuf *, size_t, const struct timespec *);
#endif
#endif /* ! _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SEM_H */
