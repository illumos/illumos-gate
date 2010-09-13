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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved	*/

#ifndef	_SYS_SEM_IMPL_H
#define	_SYS_SEM_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ipc_impl.h>
#if defined(_KERNEL) || defined(_KMEMUSER)
#include <sys/sem.h>
#include <sys/t_lock.h>
#include <sys/avl.h>
#include <sys/list.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Argument vectors for the various flavors of semsys().
 */

#define	SEMCTL	0
#define	SEMGET	1
#define	SEMOP	2
#define	SEMIDS	3
#define	SEMTIMEDOP	4

#if defined(_KERNEL) || defined(_KMEMUSER)

/*
 * There is one semaphore id data structure (semid_ds) for each set of
 * semaphores in the system.
 */
typedef struct ksemid {
	kipc_perm_t	sem_perm;	/* operation permission struct */
	struct sem	*sem_base;	/* ptr to first semaphore in set */
	ushort_t	sem_nsems;	/* # of semaphores in set */
	time_t		sem_otime;	/* last semop time */
	time_t		sem_ctime;	/* last change time */
	int		sem_binary;	/* flag indicating semaphore type */
	int		sem_maxops;	/* maximum number of operations */
	list_t		sem_undos;	/* list of undo structures */
} ksemid_t;

/*
 * There is one semaphore structure (sem) for each semaphore in the system.
 */
struct sem {
	ushort_t	semval;		/* semaphore value */
	pid_t		sempid;		/* pid of last operation */
	ushort_t	semncnt;	/* # awaiting semval > cval */
	ushort_t	semzcnt;	/* # awaiting semval = 0 */
	kcondvar_t	semncnt_cv;
	kcondvar_t	semzcnt_cv;
};

/*
 * There is one undo structure per process in the system.
 */
struct sem_undo {
	avl_node_t	un_avl;		/* node in per-process avl tree */
	list_node_t	un_list;	/* ptr to next active undo structure */
	proc_t		*un_proc;	/* back-pointer to process */
	ksemid_t	*un_sp;		/* back-pointer to semaphore */
	int 		un_aoe[1];	/* adjust on exit values */
};
#endif	/* _KERNEL */

#if defined(_SYSCALL32)
/*
 * LP64 view of the ILP32 semid_ds structure
 */
struct semid_ds32 {
	struct ipc_perm32 sem_perm;	/* operation permission struct */
	caddr32_t	sem_base;	/* ptr to first semaphore in set */
	uint16_t	sem_nsems;	/* # of semaphores in set */
	time32_t	sem_otime;	/* last semop time */
	int32_t		sem_pad1;	/* reserved for time_t expansion */
	time32_t	sem_ctime;	/* last semop time */
	int32_t		sem_pad2;	/* reserved for time_t expansion */
	int32_t		sem_binary;	/* flag indicating semaphore type */
	int32_t		sem_pad3[3];	/* reserve area */
};
#endif

#ifdef _KERNEL
extern void semexit(proc_t *);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SEM_IMPL_H */
