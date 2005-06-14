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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	IPC Shared Memory Facility.
 */

#ifndef _sys_shm_h
#define _sys_shm_h

#include <sys/param.h>
/* #include <machine/mmu.h> */

/*
 *	Shared Memory Operation Flags.
 */

#define	SHM_RDONLY	010000	/* attach read-only (else read-write) */
#define	SHM_RND		020000	/* round attach address to SHMLBA */

/*
 * Shmctl Command Definitions.
 */

#define SHM_LOCK	3	/* Lock segment in core */
#define SHM_UNLOCK	4	/* Unlock segment */

/*
 *	Implementation Constants.
 */
#define	SHMLBA	PAGESIZE	/* segment low boundary address multiple */
				/* (SHMLBA must be a power of 2) */

/*
 *	Structure Definitions.
 */

/*
 *	There is a shared mem id data structure for each segment in the system.
 */

struct shmid_ds {
	struct ipc_perm	shm_perm;	/* operation permission struct */
	uint		shm_segsz;	/* size of segment in bytes */
	ushort		shm_lpid;	/* pid of last shmop */
	ushort		shm_cpid;	/* pid of creator */
	ushort		shm_nattch;	/* number of current attaches */
	time_t		shm_atime;	/* last shmat time */
	time_t		shm_dtime;	/* last shmdt time */
	time_t		shm_ctime;	/* last change time */
	struct anon_map	*shm_amp;	/* segment anon_map pointer */
};



#ifdef KERNEL
/*
 *	Permission Definitions.
 */

#define	SHM_W	0200	/* write permission */
#define	SHM_R	0400	/* read permission */

/*
 *	ipc_perm Mode Definitions.
 */

#define	SHM_INIT	001000	/* segment not yet initialized */
#define SHM_LOCKED	004000	/* shmid locked */
#define SHM_LOCKWAIT	010000	/* shmid wanted */

#define	PSHM	(PZERO + 1)	/* sleep priority */

/* define resource locking macros */
#define SHMLOCK(sp) { \
	while ((sp)->shm_perm.mode & SHM_LOCKED) { \
		(sp)->shm_perm.mode |= SHM_LOCKWAIT; \
		(void) sleep((caddr_t)(sp), PSHM); \
	} \
	(sp)->shm_perm.mode |= SHM_LOCKED; \
}

#define SHMUNLOCK(sp) { \
	(sp)->shm_perm.mode &= ~SHM_LOCKED; \
	if ((sp)->shm_perm.mode & SHM_LOCKWAIT) { \
		(sp)->shm_perm.mode &= ~SHM_LOCKWAIT; \
		curpri = PSHM; \
		wakeup((caddr_t)(sp)); \
	} \
}

/*
 *	Shared Memory information structure
 */
struct	shminfo {
	int	shmmax,		/* max shared memory segment size */
		shmmin,		/* min shared memory segment size */
		shmmni,		/* # of shared memory identifiers */
		shmseg,		/* (obsolete)                     */
		shmall;		/* (obsolete)                     */
};
struct shminfo	shminfo;	/* configuration parameters */

/*
 *	Configuration Parameters
 * These parameters are tuned by editing the system configuration file.
 * The following lines establish the default values.
 */
#ifndef	SHMSIZE
#define	SHMSIZE	1024	/* maximum shared memory segment size (in Kbytes) */
#endif
#ifndef	SHMMNI
#define	SHMMNI	100	/* # of shared memory identifiers */
#endif

/* The following parameters are assumed not to require tuning */
#define	SHMMIN	1			/* min shared memory segment size */
#define	SHMMAX	(SHMSIZE * 1024)	/* max shared memory segment size */


/*
 * Structures allocated in machdep.c
 */
struct shmid_ds	*shmem;		/* shared memory id pool */

#endif KERNEL

#endif /*!_sys_shm_h*/
