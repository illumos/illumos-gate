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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	IPC Semaphore Facility.
 */

#ifndef _sys_sem_h
#define _sys_sem_h

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


#ifdef KERNEL
/*
 *	Implementation Constants.
 */

#define	PSEMN	(PZERO + 3)	/* sleep priority waiting for greater value */
#define	PSEMZ	(PZERO + 2)	/* sleep priority waiting for zero */

#define	SEMVMX	32767		/* semaphore maximum value */
#define	SEMAEM	16384		/* adjust on exit max value */


/*
 *	Permission Definitions.
 */

#define	SEM_A	0200	/* alter permission */
#define	SEM_R	0400	/* read permission */

/*
 *	There is one undo structure per process in the system.
 */

struct sem_undo {
	struct sem_undo	*un_np;	/* ptr to next active undo structure */
	short		un_cnt;	/* # of active entries */
	struct undo {
		short	un_aoe;	/* adjust on exit values */
		short	un_num;	/* semaphore # */
		int	un_id;	/* semid */
	}	un_ent[1];	/* (semume) undo entries (one minimum) */
};

/*
 * semaphore information structure
 */
struct	seminfo	{
	int	semmap,		/* # of entries in semaphore map */
		semmni,		/* # of semaphore identifiers */
		semmns,		/* # of semaphores in system */
		semmnu,		/* # of undo structures in system */
		semmsl,		/* max # of semaphores per id */
		semopm,		/* max # of operations per semop call */
		semume,		/* max # of undo entries per process */
		semusz,		/* size in bytes of undo structure */
		semvmx,		/* semaphore maximum value */
		semaem;		/* adjust on exit max value */
};
struct seminfo	seminfo;	/* configuration parameters */


/*
 *	Configuration Parameters
 * These parameters are tuned by editing the system configuration file.
 * The following lines establish the default values.
 */
#ifndef	SEMMNI
#define	SEMMNI	10		/* # of semaphore identifiers */
#endif
#ifndef	SEMMNS
#define	SEMMNS	60		/* # of semaphores in system */
#endif
#ifndef	SEMUME
#define	SEMUME	10		/* max # of undo entries per process */
#endif
#ifndef	SEMMNU
#define	SEMMNU	30		/* # of undo structures in system */
#endif

/* The following parameters are assumed not to require tuning */
#ifndef	SEMMAP
#define	SEMMAP	30		/* # of entries in semaphore map */
#endif
#ifndef	SEMMSL
#define	SEMMSL	SEMMNS		/* max # of semaphores per id */
#endif
#ifndef	SEMOPM
#define	SEMOPM	100		/* max # of operations per semop call */
#endif

		/* size in bytes of undo structure */
#define	SEMUSZ	(sizeof(struct sem_undo)+sizeof(struct undo)*SEMUME)


/*
 * Structures allocated in machdep.c
 */
struct semid_ds *sema;		/* semaphore id pool */
struct sem	*sem;		/* semaphore pool */
struct map	*semmap;	/* semaphore allocation map */
struct sem_undo	**sem_undo;	/* per process undo table */
int		*semu;		/* undo structure pool */

#endif KERNEL

#endif /*!_sys_sem_h*/
