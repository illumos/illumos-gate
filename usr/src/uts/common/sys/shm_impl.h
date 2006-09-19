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

#ifndef	_SYS_SHM_IMPL_H
#define	_SYS_SHM_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ipc_impl.h>
#if defined(_KERNEL) || defined(_KMEMUSER)
#include <sys/shm.h>
#include <sys/avl.h>
#include <sys/t_lock.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * shmsys system call subcodes
 */
#define	SHMAT	0
#define	SHMCTL	1
#define	SHMDT	2
#define	SHMGET	3
#define	SHMIDS	4

/*
 *	There is a shared mem id data structure (shmid_ds) for each
 *	segment in the system.
 */
#if defined(_KERNEL) || defined(_KMEMUSER)
typedef struct kshmid {
	kipc_perm_t	shm_perm;	/* operation permission struct */
	size_t		shm_segsz;	/* size of segment in bytes */
	struct anon_map	*shm_amp;	/* segment anon_map pointer */
	ushort_t	shm_lkcnt;	/* number of times it is being locked */
	pgcnt_t		shm_lkpages;	/* number of pages locked by shmctl */
	kmutex_t	shm_mlock;	/* held when locking physical pages */
					/* Therefore, protects p_lckcnt for */
					/* pages that back shm */
	pid_t		shm_lpid;	/* pid of last shmop */
	pid_t		shm_cpid;	/* pid of creator */
	ulong_t		shm_ismattch;	/* number of ISM attaches */
	time_t		shm_atime;	/* last shmat time */
	time_t		shm_dtime;	/* last shmdt time */
	time_t		shm_ctime;	/* last change time */
	struct sptinfo	*shm_sptinfo;	/* info about ISM segment */
	struct seg	*shm_sptseg;	/* pointer to ISM segment */
	long		shm_sptprot;	/* was reserved (still a "long") */
} kshmid_t;

/*
 *	Segacct Flags.
 */
#define	SHMSA_ISM	1	/* uses shared page table */

typedef struct sptinfo {
	struct as	*sptas;		/* dummy as ptr. for spt segment */
} sptinfo_t;

/*
 * Protected by p->p_lock
 */
typedef struct segacct {
	avl_node_t	sa_tree;
	caddr_t		sa_addr;
	size_t		sa_len;
	ulong_t		sa_flags;
	kshmid_t	*sa_id;
} segacct_t;

/*
 * Error codes for shmgetid().
 */
#define	SHMID_NONE	(-1)
#define	SHMID_FREE	(-2)

extern void shminit(void);
extern void shmfork(struct proc *, struct proc *);
extern void shmexit(struct proc *);
extern int shmgetid(struct proc *, caddr_t);

#endif	/* _KERNEL */

#if defined(_SYSCALL32)
/*
 * LP64 view of the ILP32 shmid_ds structure
 */
struct shmid_ds32 {
	struct ipc_perm32 shm_perm;	/* operation permission struct */
	size32_t	shm_segsz;	/* size of segment in bytes */
	caddr32_t	shm_amp;	/* segment anon_map pointer */
	uint16_t	shm_lkcnt;	/* number of times it is being locked */
	pid32_t		shm_lpid;	/* pid of last shmop */
	pid32_t		shm_cpid;	/* pid of creator */
	uint32_t	shm_nattch;	/* number of attaches */
	uint32_t	shm_cnattch;	/* number of ISM attaches */
	time32_t	shm_atime;	/* last shmat time */
	int32_t		shm_pad1;	/* reserved for time_t expansion */
	time32_t	shm_dtime;	/* last shmdt time */
	int32_t		shm_pad2;	/* reserved for time_t expansion */
	time32_t	shm_ctime;	/* last change time */
	int32_t		shm_pad3;	/* reserved for time_t expansion */
	int32_t		shm_pad4[4];	/* reserve area  */
};
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SHM_IMPL_H */
